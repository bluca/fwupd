/*
 * Copyright 2026 Luca Boccassi <luca.boccassi@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include <systemd/sd-json.h>
#include <systemd/sd-varlink-idl.h>
#include <systemd/sd-varlink.h>

#include "fu-device-private.h"
#include "fu-input-stream.h"
#include "fu-systemd-pcrlock-plugin.h"

struct _FuSystemdPcrlockPlugin {
	FuPlugin parent_instance;
	GPtrArray *unlocked; /* (element-type utf8): categories unlocked during composite_prepare */
	GHashTable *secure_boot_updates; /* device ID:GBytes */
	gboolean supports_secure_boot_update;
};

G_DEFINE_TYPE(FuSystemdPcrlockPlugin, fu_systemd_pcrlock_plugin, FU_TYPE_PLUGIN)

G_DEFINE_AUTOPTR_CLEANUP_FUNC(sd_varlink, sd_varlink_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(sd_varlink_interface, sd_varlink_interface_free)

/* The privileged Varlink service provided by systemd-pcrlock is
 * socket-activated and only present when the system was booted with a measured
 * UKI (ConditionSecurity=measured-uki) */
#define FU_SYSTEMD_PCRLOCK_VARLINK_ADDRESS "/run/systemd/io.systemd.PCRLock"

/* nocheck:name */
static const gchar *
fu_systemd_pcrlock_plugin_secure_boot_variable(FuDevice *self)
{
	const gchar *physical_id = fu_device_get_physical_id(self);

	if (physical_id == NULL)
		return NULL;
	if (g_ascii_strcasecmp(physical_id, "KEK") == 0)
		return "kek";
	if (g_ascii_strcasecmp(physical_id, "db") == 0)
		return "db";
	if (g_ascii_strcasecmp(physical_id, "dbx") == 0)
		return "dbx";
	return NULL;
}

static sd_varlink *
fu_systemd_pcrlock_plugin_connect(GError **error)
{
	const gchar *address = g_getenv("FWUPD_SYSTEMD_PCRLOCK_VARLINK_ADDRESS");
	sd_varlink *vl = NULL;
	int r;

	if (address == NULL)
		address = FU_SYSTEMD_PCRLOCK_VARLINK_ADDRESS;
	r = sd_varlink_connect_address(&vl, address);
	if (r < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to connect to %s: %s",
			    address,
			    fwupd_strerror(-r));
		return NULL;
	}
	return vl;
}

static gboolean
fu_systemd_pcrlock_plugin_check_reply(int r,
				      const char *error_id,
				      const gchar *method,
				      GError **error)
{
	if (r < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to call %s: %s",
			    method,
			    fwupd_strerror(-r));
		return FALSE;
	}
	if (error_id != NULL) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "%s returned %s",
			    method,
			    error_id);
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_systemd_pcrlock_plugin_unlock(sd_varlink *vl, const gchar *category, GError **error)
{
	const char *error_id = NULL;
	int r;

	/* Removing the .pcrlock drop-in (Lock=false) stops the regenerated policy
	 * from requiring the current measurements for this category, so the disk
	 * can still be unlocked once the update has been applied and the PCRs have
	 * changed */
	r = sd_varlink_callbo(vl,
			      "io.systemd.PCRLock.Lock",
			      /* ret_parameters= */ NULL,
			      &error_id,
			      SD_JSON_BUILD_PAIR_STRING("category", category),
			      SD_JSON_BUILD_PAIR_BOOLEAN("lock", FALSE));
	return fu_systemd_pcrlock_plugin_check_reply(r, error_id, "io.systemd.PCRLock.Lock", error);
}

static gboolean
fu_systemd_pcrlock_plugin_lock(sd_varlink *vl, const gchar *category, GError **error)
{
	const char *error_id = NULL;
	int r;

	/* opposite of fu_systemd_pcrlock_plugin_unlock() */
	r = sd_varlink_callbo(vl,
			      "io.systemd.PCRLock.Lock",
			      /* ret_parameters= */ NULL,
			      &error_id,
			      SD_JSON_BUILD_PAIR_STRING("category", category),
			      SD_JSON_BUILD_PAIR_BOOLEAN("lock", TRUE));
	return fu_systemd_pcrlock_plugin_check_reply(r, error_id, "io.systemd.PCRLock.Lock", error);
}

static gboolean
fu_systemd_pcrlock_plugin_make_policy(sd_varlink *vl, GError **error)
{
	const char *error_id = NULL;
	int r;

	/* regenerate the policy from the remaining .pcrlock drop-ins and reseal it into the TPM */
	r = sd_varlink_call(vl,
			    "io.systemd.PCRLock.MakePolicy",
			    /* parameters= */ NULL,
			    /* ret_parameters= */ NULL,
			    &error_id);
	if (r < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to call io.systemd.PCRLock.MakePolicy: %s",
			    fwupd_strerror(-r));
		return FALSE;
	}

	/* the policy was already up to date, which is not an error for us */
	if (g_strcmp0(error_id, "io.systemd.PCRLock.NoChange") == 0) {
		g_debug("systemd-pcrlock policy already up to date, nothing to do");
		return TRUE;
	}
	return fu_systemd_pcrlock_plugin_check_reply(r,
						     error_id,
						     "io.systemd.PCRLock.MakePolicy",
						     error);
}

static gboolean
fu_systemd_pcrlock_plugin_startup(FuPlugin *plugin, FuProgress *progress, GError **error)
{
	FuSystemdPcrlockPlugin *self = FU_SYSTEMD_PCRLOCK_PLUGIN(plugin);
	FuContext *ctx = fu_plugin_get_context(plugin);
	const char *error_id = NULL;
	const char *description;
	sd_json_variant *reply = NULL;
	const gchar *address = g_getenv("FWUPD_SYSTEMD_PCRLOCK_VARLINK_ADDRESS");
	int r;
	g_autoptr(sd_varlink) vl = NULL;
	g_autoptr(sd_varlink_interface) interface = NULL;
	gboolean supports_lock = FALSE;
	gboolean supports_prepare = FALSE;

	/* the plugin is only useful when systemd-pcrlock is protecting this system */
	if (!fu_context_has_flag(ctx, FU_CONTEXT_FLAG_FDE_SYSTEMD_PCRLOCK)) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "systemd-pcrlock is not being used to protect this system");
		return FALSE;
	}

	if (address == NULL)
		address = FU_SYSTEMD_PCRLOCK_VARLINK_ADDRESS;

	r = sd_varlink_connect_address(&vl, address);
	if (r < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to connect to %s: %s",
			    address,
			    fwupd_strerror(-r));
		return FALSE;
	}

	/* introspect the interface: an older systemd-pcrlock does not implement the
	 * Lock method (or the interface at all), so disable the plugin rather than
	 * failing an update later on */
	r = sd_varlink_callbo(vl,
			      "org.varlink.service.GetInterfaceDescription",
			      &reply,
			      &error_id,
			      SD_JSON_BUILD_PAIR_STRING("interface", "io.systemd.PCRLock"));
	if (r < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to introspect io.systemd.PCRLock: %s",
			    fwupd_strerror(-r));
		return FALSE;
	}
	if (error_id == NULL) {
		description = sd_json_variant_string(sd_json_variant_by_key(reply, "description"));
		if (description == NULL) {
			g_set_error_literal(
			    error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "io.systemd.PCRLock introspection returned no description");
			return FALSE;
		}
		r = sd_varlink_idl_parse(description,
					 /* reterr_line= */ NULL,
					 /* reterr_column= */ NULL,
					 &interface);
		if (r < 0) {
			g_set_error(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "failed to parse the io.systemd.PCRLock interface: %s",
				    fwupd_strerror(-r));
			return FALSE;
		}
		for (const sd_varlink_symbol *const *symbol = interface->symbols; *symbol != NULL;
		     symbol++) {
			if ((*symbol)->symbol_type != SD_VARLINK_METHOD)
				continue;
			if (g_strcmp0((*symbol)->name, "Lock") == 0)
				supports_lock = TRUE;
			else if (g_strcmp0((*symbol)->name, "PrepareSecureBootUpdate") == 0)
				supports_prepare = TRUE;
		}
	} else if (g_strcmp0(error_id, "org.varlink.service.InterfaceNotFound") != 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to introspect io.systemd.PCRLock: %s",
			    error_id);
		return FALSE;
	}

	if (!supports_lock) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    "systemd-pcrlock is too old to support the Lock method");
		return FALSE;
	}
	self->supports_secure_boot_update = supports_prepare;
	if (!self->supports_secure_boot_update)
		g_debug("systemd-pcrlock does not support Secure Boot update prediction, using unlock fallback");
	return TRUE;
}

static gboolean
fu_systemd_pcrlock_plugin_prepare(FuPlugin *plugin,
				  FuDevice *device,
				  FuProgress *progress,
				  FwupdInstallFlags flags,
				  GError **error)
{
	FuSystemdPcrlockPlugin *self = FU_SYSTEMD_PCRLOCK_PLUGIN(plugin);
	GInputStream *stream;
	const gchar *device_id;
	const gchar *variable;
	g_autoptr(GBytes) data = NULL;

	if (!self->supports_secure_boot_update ||
	    !fu_device_has_flag(device, FWUPD_DEVICE_FLAG_AFFECTS_FDE) ||
	    !fu_device_has_private_flag(device, FU_DEVICE_PRIVATE_FLAG_REQUIRES_UNLOCK_SECUREBOOT))
		return TRUE;
	variable = fu_systemd_pcrlock_plugin_secure_boot_variable(device);
	if (variable == NULL)
		return TRUE;
	device_id = fu_device_get_id(device);
	if (device_id == NULL) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "Secure Boot update device has no ID");
		return FALSE;
	}
	if (g_hash_table_contains(self->secure_boot_updates, device_id)) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_BUSY,
			    "Secure Boot update already active for %s",
			    device_id);
		return FALSE;
	}
	stream = fu_device_get_update_stream(device);
	if (stream == NULL)
		data = g_bytes_new_static(NULL, 0);
	else {
		data = fu_input_stream_read_bytes(stream, 0, G_MAXSIZE, NULL, error);
		if (data == NULL)
			return FALSE;
	}
	g_hash_table_replace(self->secure_boot_updates,
			     g_strdup(device_id),
			     g_steal_pointer(&data));
	return TRUE;
}

static gboolean
fu_systemd_pcrlock_plugin_apply_secure_boot_update(FuSystemdPcrlockPlugin *self,
						   FuDevice *device,
						   GError **error)
{
	const gchar *device_id = fu_device_get_id(device);
	const gchar *error_id = NULL;
	const gchar *variable;
	GBytes *data;
	g_autoptr(sd_varlink) vl = NULL;
	int r;

	if (device_id == NULL)
		return TRUE;
	data = g_hash_table_lookup(self->secure_boot_updates, device_id);
	if (data == NULL)
		return TRUE;
	variable = fu_systemd_pcrlock_plugin_secure_boot_variable(device);
	if (variable == NULL)
		return TRUE;
	vl = fu_systemd_pcrlock_plugin_connect(error);
	if (vl == NULL)
		return FALSE;
	r = sd_varlink_callbo(vl,
			      "io.systemd.PCRLock.PrepareSecureBootUpdate",
			      NULL,
			      &error_id,
			      SD_JSON_BUILD_PAIR_STRING("variable", variable),
			      SD_JSON_BUILD_PAIR_BASE64(
				  "data", g_bytes_get_data(data, NULL), g_bytes_get_size(data)));
	if (!fu_systemd_pcrlock_plugin_check_reply(r,
						  error_id,
						  "io.systemd.PCRLock.PrepareSecureBootUpdate",
						  error))
		return FALSE;
	g_hash_table_remove(self->secure_boot_updates, device_id);
	return TRUE;
}

static gboolean
fu_systemd_pcrlock_plugin_cleanup(FuPlugin *plugin,
				  FuDevice *device,
				  FuProgress *progress,
				  FwupdInstallFlags flags,
				  GError **error)
{
	return fu_systemd_pcrlock_plugin_apply_secure_boot_update(
	    FU_SYSTEMD_PCRLOCK_PLUGIN(plugin), device, error);
}

/* re-lock a single measurement, if it was one we unlocked during prepare */
static gboolean
fu_systemd_pcrlock_plugin_relock_category(FuSystemdPcrlockPlugin *self,
					  sd_varlink *vl,
					  const gchar *category,
					  GError **error)
{
	if (!g_ptr_array_find_with_equal_func(self->unlocked, category, g_str_equal, NULL))
		return TRUE;
	return fu_systemd_pcrlock_plugin_lock(vl, category, error);
}

/* remember a measurement we unlocked, so it can be re-locked on failure */
static void
fu_systemd_pcrlock_plugin_add_unlocked_category(FuSystemdPcrlockPlugin *self, const gchar *category)
{
	g_ptr_array_add(self->unlocked, g_strdup(category));
}

/* Used to rollback the unlocks if any step of prepare fails, to avoid leaving
 * intermediate state around; the sealed policy is only changed on success. */
typedef struct {
	FuSystemdPcrlockPlugin *self; /* noref */
	sd_varlink *vl;		      /* noref */
} FuSystemdPcrlockRollback;

static void
fu_systemd_pcrlock_plugin_rollback_free(FuSystemdPcrlockRollback *rollback)
{
	/* disarmed on success by clearing vl; otherwise re-lock everything we removed */
	if (rollback->vl != NULL) {
		for (guint i = 0; i < rollback->self->unlocked->len; i++) {
			const gchar *category = g_ptr_array_index(rollback->self->unlocked, i);
			g_autoptr(GError) error_local = NULL;
			if (!fu_systemd_pcrlock_plugin_lock(rollback->vl, category, &error_local))
				g_debug("failed to re-lock %s: %s", category, error_local->message);
		}
		g_ptr_array_set_size(rollback->self->unlocked, 0);
	}
	g_free(rollback);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(FuSystemdPcrlockRollback, fu_systemd_pcrlock_plugin_rollback_free)

static gboolean
fu_systemd_pcrlock_plugin_component_locked(sd_json_variant *components, const gchar *needle)
{
	/* systemd prefixes component ids with an ordering number and may split them into an
	 * early and a late part, e.g. "250-firmware-code-early" and "550-firmware-code-late",
	 * so match the stable middle part of the id */
	for (size_t i = 0; i < sd_json_variant_elements(components); i++) {
		sd_json_variant *component = sd_json_variant_by_index(components, i);
		sd_json_variant *variants = sd_json_variant_by_key(component, "variants");
		const char *id = sd_json_variant_string(sd_json_variant_by_key(component, "id"));

		/* a component with no variants defines no .pcrlock file, so locks nothing */
		if (variants == NULL || sd_json_variant_elements(variants) == 0)
			continue;

		if (id != NULL && g_strstr_len(id, -1, needle) != NULL)
			return TRUE;
	}
	return FALSE;
}

static gboolean
fu_systemd_pcrlock_plugin_relock(FuSystemdPcrlockPlugin *self,
				 gboolean unlock_firmware,
				 gboolean unlock_secureboot,
				 GError **error)
{
	int r;
	const gchar *address = g_getenv("FWUPD_SYSTEMD_PCRLOCK_VARLINK_ADDRESS");
	const char *error_id = NULL;
	sd_json_variant *components = NULL;
	gboolean firmware_code_locked = FALSE;
	gboolean firmware_config_locked = FALSE;
	gboolean secureboot_policy_locked = FALSE;
	gboolean secureboot_authority_locked = FALSE;
	g_autoptr(sd_varlink) vl = NULL;
	g_autoptr(FuSystemdPcrlockRollback) rollback = g_new0(FuSystemdPcrlockRollback, 1);

	/* forget anything left behind by an earlier attempt */
	rollback->self = self;
	g_ptr_array_set_size(self->unlocked, 0);

	if (address == NULL)
		address = FU_SYSTEMD_PCRLOCK_VARLINK_ADDRESS;

	r = sd_varlink_connect_address(&vl, address);
	if (r < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to connect to %s: %s",
			    address,
			    fwupd_strerror(-r));
		return FALSE;
	}

	/* Find out which of the measurements are actually locked, so that we only unlock
	 * (and later re-lock on failure) the ones that pcrlock is currently enforcing. */
	r = sd_varlink_collect(vl,
			       "io.systemd.PCRLock.ListComponents",
			       /* parameters= */ NULL,
			       &components,
			       &error_id);
	if (!fu_systemd_pcrlock_plugin_check_reply(r,
						   error_id,
						   "io.systemd.PCRLock.ListComponents",
						   error))
		return FALSE;
	firmware_code_locked =
	    fu_systemd_pcrlock_plugin_component_locked(components, "firmware-code");
	firmware_config_locked =
	    fu_systemd_pcrlock_plugin_component_locked(components, "firmware-config");
	secureboot_policy_locked =
	    fu_systemd_pcrlock_plugin_component_locked(components, "secureboot-policy");
	secureboot_authority_locked =
	    fu_systemd_pcrlock_plugin_component_locked(components, "secureboot-authority");

	/* queries are done and connection is up, arm the rollback */
	rollback->vl = vl;

	/* remove the drop-ins for the affected measurements (firmware = PCRs 0, 2, 4
	 * and 1, 3, 5 and SecureBoot = PCR 7), remembering each one so it can be re-locked
	 * if a later step fails or the update itself does not complete */
	if (unlock_firmware && firmware_code_locked) {
		if (!fu_systemd_pcrlock_plugin_unlock(vl, "firmwareCode", error))
			return FALSE;
		fu_systemd_pcrlock_plugin_add_unlocked_category(self, "firmwareCode");
	}
	if (unlock_firmware && firmware_config_locked) {
		if (!fu_systemd_pcrlock_plugin_unlock(vl, "firmwareConfig", error))
			return FALSE;
		fu_systemd_pcrlock_plugin_add_unlocked_category(self, "firmwareConfig");
	}
	if (unlock_secureboot && secureboot_policy_locked) {
		if (!fu_systemd_pcrlock_plugin_unlock(vl, "secureBootPolicy", error))
			return FALSE;
		fu_systemd_pcrlock_plugin_add_unlocked_category(self, "secureBootPolicy");
	}
	if (unlock_secureboot && secureboot_authority_locked) {
		if (!fu_systemd_pcrlock_plugin_unlock(vl, "secureBootAuthority", error))
			return FALSE;
		fu_systemd_pcrlock_plugin_add_unlocked_category(self, "secureBootAuthority");
	}

	/* if nothing was actually unlocked the policy is unchanged, so avoid regenerating
	 * it, which would needlessly reseal the TPM and could fail */
	if (self->unlocked->len > 0) {
		if (!fu_systemd_pcrlock_plugin_make_policy(vl, error))
			return FALSE;
	}

	/* success: keep the loosened policy, and disarm the rollback so the unlocked
	 * measurements are remembered for composite_cleanup instead of re-locked now */
	rollback->vl = NULL;
	return TRUE;
}

static gboolean
fu_systemd_pcrlock_plugin_composite_prepare(FuPlugin *plugin, GPtrArray *devices, GError **error)
{
	FuSystemdPcrlockPlugin *self = FU_SYSTEMD_PCRLOCK_PLUGIN(plugin);
	gboolean unlock_firmware = FALSE;
	gboolean unlock_secureboot = FALSE;

	/* work out what kind of measurements the updates about to be applied will change */
	for (guint i = 0; i < devices->len; i++) {
		FuDevice *device = g_ptr_array_index(devices, i);
		gboolean fw;
		gboolean sb;

		/* only devices that change the measured-boot state */
		if (!fu_device_has_flag(device, FWUPD_DEVICE_FLAG_AFFECTS_FDE))
			continue;

		/* plugins opt in to the specific measurements their updates change */
		fw = fu_device_has_private_flag(device,
						FU_DEVICE_PRIVATE_FLAG_REQUIRES_UNLOCK_FIRMWARE);
		sb = fu_device_has_private_flag(device,
						FU_DEVICE_PRIVATE_FLAG_REQUIRES_UNLOCK_SECUREBOOT);

		/* affects the measured-boot state but did not say how, so be conservative */
		if (!fw && !sb) {
			fw = TRUE;
			sb = TRUE;
		}
		if (fw)
			unlock_firmware = TRUE;
		if (sb &&
		    (!self->supports_secure_boot_update ||
		     fu_systemd_pcrlock_plugin_secure_boot_variable(device) == NULL))
			unlock_secureboot = TRUE;
	}

	/* nothing being updated changes a measurement that pcrlock is locking */
	if (!unlock_firmware && !unlock_secureboot)
		return TRUE;

	/* Loosen and regenerate the policy before the update is applied, as if this
	 * fails the update must be aborted, as otherwise the measurements would
	 * change on the next boot and no longer satisfy the still-sealed policy,
	 * and the disk could not be unlocked */
	if (!fu_systemd_pcrlock_plugin_relock(self, unlock_firmware, unlock_secureboot, error)) {
		g_prefix_error_literal(error,
				       "failed to update systemd-pcrlock policy for firmware "
				       "update: ");
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_systemd_pcrlock_plugin_composite_cleanup(FuPlugin *plugin, GPtrArray *devices, GError **error)
{
	FuSystemdPcrlockPlugin *self = FU_SYSTEMD_PCRLOCK_PLUGIN(plugin);
	const gchar *address = g_getenv("FWUPD_SYSTEMD_PCRLOCK_VARLINK_ADDRESS");
	gboolean relock_firmware = FALSE;
	gboolean relock_secureboot = FALSE;
	int r;
	g_autoptr(GError) error_first = NULL;
	g_autoptr(sd_varlink) vl = NULL;

	/* the policy was not loosened during prepare, so there is nothing to undo */
	if (self->unlocked->len == 0)
		goto out;

	/* Only re-lock the measurements whose update failed, keeping the loosened policy for
	 * the ones that succeeded. Classify each failed device the same way as
	 * composite_prepare did when deciding what to unlock. */
	for (guint i = 0; i < devices->len; i++) {
		FuDevice *device = g_ptr_array_index(devices, i);
		FwupdUpdateState state;
		gboolean fw;
		gboolean sb;

		if (!fu_device_has_flag(device, FWUPD_DEVICE_FLAG_AFFECTS_FDE))
			continue;
		state = fu_device_get_update_state(device);
		if (state != FWUPD_UPDATE_STATE_FAILED &&
		    state != FWUPD_UPDATE_STATE_FAILED_TRANSIENT)
			continue;

		fw = fu_device_has_private_flag(device,
						FU_DEVICE_PRIVATE_FLAG_REQUIRES_UNLOCK_FIRMWARE);
		sb = fu_device_has_private_flag(device,
						FU_DEVICE_PRIVATE_FLAG_REQUIRES_UNLOCK_SECUREBOOT);

		/* affects the measured-boot state but did not say how, so be conservative */
		if (!fw && !sb) {
			fw = TRUE;
			sb = TRUE;
		}
		if (fw)
			relock_firmware = TRUE;
		if (sb)
			relock_secureboot = TRUE;
	}
	if (!relock_firmware && !relock_secureboot) {
		g_ptr_array_set_size(self->unlocked, 0);
		goto out;
	}

	/* Re-lock the measurements belonging to the failed updates and regenerate the policy
	 * to restore the protection that was in place before the update. */
	if (address == NULL)
		address = FU_SYSTEMD_PCRLOCK_VARLINK_ADDRESS;
	r = sd_varlink_connect_address(&vl, address);
	if (r < 0) {
		g_autoptr(GError) error_local = NULL;
		g_set_error(&error_local,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to connect to %s: %s",
			    address,
			    fwupd_strerror(-r));
		if (error_first == NULL)
			error_first = g_steal_pointer(&error_local);
		else
			g_debug("failed to connect while restoring pcrlock policy: %s",
				error_local->message);
		goto out;
	}
	if (relock_firmware) {
		g_autoptr(GError) error_local = NULL;
		if (!fu_systemd_pcrlock_plugin_relock_category(
				self, vl, "firmwareCode", &error_local)) {
			if (error_first == NULL)
				error_first = g_steal_pointer(&error_local);
			else
				g_debug("failed to re-lock firmware code: %s", error_local->message);
		}
		g_clear_error(&error_local);
		if (!fu_systemd_pcrlock_plugin_relock_category(
				self, vl, "firmwareConfig", &error_local)) {
			if (error_first == NULL)
				error_first = g_steal_pointer(&error_local);
			else
				g_debug("failed to re-lock firmware configuration: %s",
					error_local->message);
		}
	}
	if (relock_secureboot) {
		g_autoptr(GError) error_local = NULL;
		if (!fu_systemd_pcrlock_plugin_relock_category(
				self, vl, "secureBootPolicy", &error_local)) {
			if (error_first == NULL)
				error_first = g_steal_pointer(&error_local);
			else
				g_debug("failed to re-lock Secure Boot policy: %s",
					error_local->message);
		}
		g_clear_error(&error_local);
		if (!fu_systemd_pcrlock_plugin_relock_category(
				self, vl, "secureBootAuthority", &error_local)) {
			if (error_first == NULL)
				error_first = g_steal_pointer(&error_local);
			else
				g_debug("failed to re-lock Secure Boot authority: %s",
					error_local->message);
		}
	}
	{
		g_autoptr(GError) error_local = NULL;
		if (!fu_systemd_pcrlock_plugin_make_policy(vl, &error_local)) {
			if (error_first == NULL)
				error_first = g_steal_pointer(&error_local);
			else
				g_debug("failed to regenerate pcrlock policy during cleanup: %s",
					error_local->message);
		}
	}

out:
	/* Discard payloads for updates that never reached their per-device cleanup callback. */
	for (guint i = 0; i < devices->len; i++) {
		FuDevice *device = g_ptr_array_index(devices, i);
		const gchar *device_id = fu_device_get_id(device);

		if (device_id != NULL)
			g_hash_table_remove(self->secure_boot_updates, device_id);
	}
	if (error_first != NULL) {
		g_propagate_error(error, g_steal_pointer(&error_first));
		return FALSE;
	}
	g_ptr_array_set_size(self->unlocked, 0);
	return TRUE;
}

static void
fu_systemd_pcrlock_plugin_init(FuSystemdPcrlockPlugin *self)
{
	self->unlocked = g_ptr_array_new_with_free_func(g_free);
	self->secure_boot_updates =
	    g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_bytes_unref);
}

static void
fu_systemd_pcrlock_plugin_finalize(GObject *obj)
{
	FuSystemdPcrlockPlugin *self = FU_SYSTEMD_PCRLOCK_PLUGIN(obj);
	g_ptr_array_unref(self->unlocked);
	g_hash_table_unref(self->secure_boot_updates);
	G_OBJECT_CLASS(fu_systemd_pcrlock_plugin_parent_class)->finalize(obj);
}

static void
fu_systemd_pcrlock_plugin_class_init(FuSystemdPcrlockPluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	FuPluginClass *plugin_class = FU_PLUGIN_CLASS(klass);
	object_class->finalize = fu_systemd_pcrlock_plugin_finalize;
	plugin_class->startup = fu_systemd_pcrlock_plugin_startup;
	plugin_class->prepare = fu_systemd_pcrlock_plugin_prepare;
	plugin_class->cleanup = fu_systemd_pcrlock_plugin_cleanup;
	plugin_class->composite_prepare = fu_systemd_pcrlock_plugin_composite_prepare;
	plugin_class->composite_cleanup = fu_systemd_pcrlock_plugin_composite_cleanup;
}
