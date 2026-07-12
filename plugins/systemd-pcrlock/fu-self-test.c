/*
 * Copyright 2026 Luca Boccassi <luca.boccassi@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <systemd/sd-event.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink-idl.h>
#include <systemd/sd-varlink.h>
#include <unistd.h>

#include "fu-context-private.h"
#include "fu-device-private.h"
#include "fu-memory-input-stream.h"
#include "fu-plugin-private.h"
#include "fu-systemd-pcrlock-plugin.h"

G_DEFINE_AUTOPTR_CLEANUP_FUNC(sd_event, sd_event_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(sd_varlink_interface, sd_varlink_interface_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(sd_varlink_server, sd_varlink_server_unref)

typedef struct {
	const gchar *name;
	const gchar *physical_id;
	const gchar *category;
	const gchar *categories;
} FuSystemdPcrlockTestCase;

typedef struct {
	const gchar *category;
	const gchar *data;
	guint update_calls;
	guint unlock_calls;
	guint make_policy_calls;
} FuSystemdPcrlockTestServer;

static FuDevice *
fu_systemd_pcrlock_test_device_new(FuContext *ctx, const gchar *plugin_name, gboolean affects_fde)
{
	FuDevice *device = fu_device_new(ctx);
	fu_device_set_plugin(device, plugin_name);
	if (affects_fde)
		fu_device_add_flag(device, FWUPD_DEVICE_FLAG_AFFECTS_FDE);
	return device;
}

/* systemd-pcrlock is not protecting this system, so the plugin disables itself
 * by failing startup */
static void
fu_systemd_pcrlock_plugin_startup_not_used_func(void)
{
	gboolean ret;
	g_autoptr(FuContext) ctx = fu_context_new();
	g_autoptr(FuPlugin) plugin = fu_plugin_new_from_gtype(FU_TYPE_SYSTEMD_PCRLOCK_PLUGIN, ctx);
	g_autoptr(FuProgress) progress = fu_progress_new(G_STRLOC);
	g_autoptr(GError) error = NULL;

	/* FU_CONTEXT_FLAG_FDE_SYSTEMD_PCRLOCK is deliberately not set */
	ret = fu_plugin_runner_startup(plugin, progress, &error);
	g_assert_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED);
	g_assert_false(ret);
}

/* pcrlock is protecting the system but the systemd-pcrlock service cannot be
 * reached, so the plugin disables itself by failing startup */
static void
fu_systemd_pcrlock_plugin_startup_no_service_func(void)
{
	gboolean ret;
	g_autoptr(FuContext) ctx = fu_context_new();
	g_autoptr(FuPlugin) plugin = fu_plugin_new_from_gtype(FU_TYPE_SYSTEMD_PCRLOCK_PLUGIN, ctx);
	g_autoptr(FuProgress) progress = fu_progress_new(G_STRLOC);
	g_autoptr(GError) error = NULL;

	fu_context_add_flag(ctx, FU_CONTEXT_FLAG_FDE_SYSTEMD_PCRLOCK);
	ret = fu_plugin_runner_startup(plugin, progress, &error);
	g_assert_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED);
	g_assert_false(ret);
}

/* pcrlock is protecting the system, but nothing being updated changes a measured
 * boot state, so the sealed policy must be left untouched */
static void
fu_systemd_pcrlock_plugin_no_affects_fde_func(void)
{
	gboolean ret;
	g_autoptr(FuContext) ctx = fu_context_new();
	g_autoptr(FuPlugin) plugin = fu_plugin_new_from_gtype(FU_TYPE_SYSTEMD_PCRLOCK_PLUGIN, ctx);
	g_autoptr(FuDevice) device = fu_systemd_pcrlock_test_device_new(ctx, "test", FALSE);
	g_autoptr(GPtrArray) devices =
	    g_ptr_array_new_with_free_func((GDestroyNotify)g_object_unref);
	g_autoptr(GError) error = NULL;

	g_ptr_array_add(devices, g_steal_pointer(&device));

	fu_context_add_flag(ctx, FU_CONTEXT_FLAG_FDE_SYSTEMD_PCRLOCK);
	ret = fu_plugin_runner_composite_prepare(plugin, devices, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
}

/* pcrlock is protecting the system and a SecureBoot database update is about to
 * be applied, so the plugin must try to loosen the policy before the write, and
 * when the systemd-pcrlock service cannot be reached the whole update has to be
 * aborted (rather than silently continuing and leaving the disk unlockable) */
static void
fu_systemd_pcrlock_plugin_abort_on_error_func(void)
{
	gboolean ret;
	g_autoptr(FuContext) ctx = fu_context_new();
	g_autoptr(FuPlugin) plugin = fu_plugin_new_from_gtype(FU_TYPE_SYSTEMD_PCRLOCK_PLUGIN, ctx);
	g_autoptr(FuDevice) device = fu_systemd_pcrlock_test_device_new(ctx, "uefi_dbx", TRUE);
	g_autoptr(GPtrArray) devices =
	    g_ptr_array_new_with_free_func((GDestroyNotify)g_object_unref);
	g_autoptr(GError) error = NULL;

	g_ptr_array_add(devices, g_steal_pointer(&device));

	fu_context_add_flag(ctx, FU_CONTEXT_FLAG_FDE_SYSTEMD_PCRLOCK);
	ret = fu_plugin_runner_composite_prepare(plugin, devices, &error);
	g_assert_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED);
	g_assert_nonnull(g_strstr_len(error->message, -1, "systemd-pcrlock policy"));
	g_assert_false(ret);
}

static int
fu_systemd_pcrlock_test_lock(sd_varlink *link,
			     sd_json_variant *parameters,
			     sd_varlink_method_flags_t flags,
			     void *userdata)
{
	FuSystemdPcrlockTestServer *server =
	    sd_varlink_server_get_userdata(sd_varlink_get_server(link));
	const gchar *category =
	    sd_json_variant_string(sd_json_variant_by_key(parameters, "category"));
	sd_json_variant *lock = sd_json_variant_by_key(parameters, "lock");

	if (server->category == NULL) {
		g_assert_cmpstr(category, ==, "secureBootPolicy");
		g_assert_true(sd_json_variant_is_boolean(lock));
		g_assert_false(sd_json_variant_boolean(lock));
		g_assert_null(sd_json_variant_by_key(parameters, "filename"));
		g_assert_null(sd_json_variant_by_key(parameters, "data"));
		server->unlock_calls++;
	} else {
		g_assert_cmpstr(category, ==, server->category);
		g_assert_true(lock == NULL || sd_json_variant_boolean(lock));
		g_assert_cmpstr(
		    sd_json_variant_string(sd_json_variant_by_key(parameters, "filename")),
		    ==,
		    "fwupd.pcrlock");
		g_assert_cmpstr(sd_json_variant_string(sd_json_variant_by_key(parameters, "data")),
				==,
				server->data);
		g_assert_null(sd_json_variant_by_key(parameters, "variable"));
		server->update_calls++;
	}
	return sd_varlink_reply(link, NULL);
}

static int
fu_systemd_pcrlock_test_list_components(sd_varlink *link,
					sd_json_variant *parameters,
					sd_varlink_method_flags_t flags,
					void *userdata)
{
	return sd_varlink_replybo(
	    link,
	    SD_JSON_BUILD_PAIR_STRING("id", "240-secureboot-policy"),
	    SD_JSON_BUILD_PAIR("variants",
			       SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(
				   SD_JSON_BUILD_PAIR_STRING("id", "generated")))));
}

static int
fu_systemd_pcrlock_test_make_policy(sd_varlink *link,
				    sd_json_variant *parameters,
				    sd_varlink_method_flags_t flags,
				    void *userdata)
{
	FuSystemdPcrlockTestServer *server =
	    sd_varlink_server_get_userdata(sd_varlink_get_server(link));

	server->make_policy_calls++;
	return sd_varlink_reply(link, NULL);
}

static int
fu_systemd_pcrlock_test_stop(sd_event_source *source, int fd, uint32_t revents, void *userdata)
{
	return sd_event_exit(sd_event_source_get_event(source), 0);
}

static gpointer
fu_systemd_pcrlock_test_run(gpointer userdata)
{
	g_assert_cmpint(sd_event_loop(userdata), ==, 0);
	return NULL;
}

static void
fu_systemd_pcrlock_plugin_secure_boot_update_func(gconstpointer userdata)
{
	const FuSystemdPcrlockTestCase *test_case = userdata;
	const gchar *categories = test_case->categories;
	const guint8 payload[] = {0x00, 0xff, 0x01, 0x42, 0x80};
	guint64 stop = 1;
	gint stop_fd;
	gboolean ret;
	GThread *thread;
	FuSystemdPcrlockTestServer state = {
	    .category = test_case->category,
	    .data = "AP8BQoA=",
	};
	g_autofree gchar *address =
	    g_strdup_printf("@fwupd-pcrlock-%u-%08x", (guint)getpid(), (guint)g_test_rand_int());
	g_autofree gchar *description = NULL;
	g_autoptr(sd_varlink_interface) interface = NULL;
	g_autoptr(sd_event) event = NULL;
	g_autoptr(sd_varlink_server) server = NULL;
	g_autoptr(FuContext) ctx = fu_context_new();
	g_autoptr(FuPlugin) plugin = fu_plugin_new_from_gtype(FU_TYPE_SYSTEMD_PCRLOCK_PLUGIN, ctx);
	g_autoptr(FuDevice) device = fu_systemd_pcrlock_test_device_new(ctx, "test", TRUE);
	g_autoptr(FuProgress) progress = fu_progress_new(G_STRLOC);
	g_autoptr(FuInputStream) stream =
	    fu_memory_input_stream_new_from_data(payload, sizeof(payload), NULL);
	g_autoptr(GPtrArray) devices = g_ptr_array_new();
	g_autoptr(GError) error = NULL;

	if (categories == NULL)
		categories = ", secureBootKek, secureBootDb, secureBootDbx";
	description = g_strdup_printf(
	    "interface io.systemd.PCRLock\n"
	    "type LockCategory (firmwareCode, firmwareConfig, secureBootPolicy, "
	    "secureBootAuthority%s)\n"
	    "method Lock(category: LockCategory, lock: ?bool%s) -> ()\n"
	    "method ListComponents() -> (id: string, variants: []object)\n"
	    "method MakePolicy() -> ()\n",
	    categories,
	    categories[0] != '\0' ? ", filename: ?string, data: ?string, regenerate: ?bool" : "");
	g_assert_cmpint(sd_varlink_idl_parse(description, NULL, NULL, &interface), >=, 0);
	g_assert_cmpint(sd_event_new(&event), >=, 0);
	g_assert_cmpint(sd_varlink_server_new(&server, 0), >=, 0);
	g_assert_cmpint(sd_varlink_server_add_interface(server, interface), >=, 0);
	g_assert_cmpint(sd_varlink_server_bind_method(server,
						      "io.systemd.PCRLock.Lock",
						      fu_systemd_pcrlock_test_lock),
			>=,
			0);
	g_assert_cmpint(sd_varlink_server_bind_method(server,
						      "io.systemd.PCRLock.ListComponents",
						      fu_systemd_pcrlock_test_list_components),
			>=,
			0);
	g_assert_cmpint(sd_varlink_server_bind_method(server,
						      "io.systemd.PCRLock.MakePolicy",
						      fu_systemd_pcrlock_test_make_policy),
			>=,
			0);
	sd_varlink_server_set_userdata(server, &state);
	g_assert_cmpint(sd_varlink_server_listen_address(server, address, 0600), >=, 0);
	g_assert_cmpint(sd_varlink_server_attach_event(server, event, 0), >=, 0);
	stop_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	g_assert_cmpint(stop_fd, >=, 0);
	g_assert_cmpint(
	    sd_event_add_io(event, NULL, stop_fd, EPOLLIN, fu_systemd_pcrlock_test_stop, NULL),
	    >=,
	    0);
	g_assert_true(g_setenv("FWUPD_SYSTEMD_PCRLOCK_VARLINK_ADDRESS", address, TRUE));
	thread = g_thread_new("pcrlock-varlink", fu_systemd_pcrlock_test_run, event);

	fu_context_add_flag(ctx, FU_CONTEXT_FLAG_FDE_SYSTEMD_PCRLOCK);
	fu_device_set_physical_id(device, test_case->physical_id);
	fu_device_set_id(device, "systemd-pcrlock-test");
	fu_device_add_private_flag(device, FU_DEVICE_PRIVATE_FLAG_REQUIRES_UNLOCK_SECUREBOOT);
	fu_device_set_update_stream(device, stream);
	g_ptr_array_add(devices, device);
	ret = fu_plugin_runner_startup(plugin, progress, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	ret = fu_plugin_runner_composite_prepare(plugin, devices, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	ret = fu_plugin_runner_prepare(plugin, device, progress, FWUPD_INSTALL_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	ret = fu_plugin_runner_cleanup(plugin, device, progress, FWUPD_INSTALL_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_true(ret);
	ret = fu_plugin_runner_cleanup(plugin, device, progress, FWUPD_INSTALL_FLAG_NONE, &error);
	g_assert_no_error(error);
	g_assert_true(ret);

	g_assert_cmpint(write(stop_fd, &stop, sizeof(stop)), ==, sizeof(stop));
	g_thread_join(thread);
	g_assert_cmpint(close(stop_fd), ==, 0);
	g_assert_cmpuint(state.update_calls, ==, test_case->category != NULL ? 1 : 0);
	g_assert_cmpuint(state.unlock_calls, ==, test_case->category == NULL ? 1 : 0);
	g_assert_cmpuint(state.make_policy_calls, ==, test_case->category == NULL ? 1 : 0);
	g_assert_true(g_setenv("FWUPD_SYSTEMD_PCRLOCK_VARLINK_ADDRESS",
			       "/nonexistent/fwupd-systemd-pcrlock-self-test/io.systemd.PCRLock",
			       TRUE));
}

int
main(int argc, char **argv)
{
	const FuSystemdPcrlockTestCase test_cases[] = {
	    {"kek", "KEK", "secureBootKek", NULL},
	    {"db", "DB", "secureBootDb", NULL},
	    {"dbx", "dbx", "secureBootDbx", NULL},
	    {"legacy", "db", NULL, ""},
	    {"partial", "db", NULL, ", secureBootKek"},
	};

	(void)g_setenv("G_TEST_SRCDIR", SRCDIR, FALSE);
	(void)g_setenv("FWUPD_SYSTEMD_PCRLOCK_VARLINK_ADDRESS",
		       "/nonexistent/fwupd-systemd-pcrlock-self-test/io.systemd.PCRLock",
		       TRUE);

	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/systemd-pcrlock/startup{not-pcrlock}",
			fu_systemd_pcrlock_plugin_startup_not_used_func);
	g_test_add_func("/systemd-pcrlock/startup{no-service}",
			fu_systemd_pcrlock_plugin_startup_no_service_func);
	g_test_add_func("/systemd-pcrlock/composite-prepare{no-affects-fde}",
			fu_systemd_pcrlock_plugin_no_affects_fde_func);
	g_test_add_func("/systemd-pcrlock/composite-prepare{abort-on-error}",
			fu_systemd_pcrlock_plugin_abort_on_error_func);
	for (guint idx = 0; idx < G_N_ELEMENTS(test_cases); idx++) {
		g_autofree gchar *path =
		    g_strdup_printf("/systemd-pcrlock/secure-boot-update/%s", test_cases[idx].name);
		g_test_add_data_func(path,
				     &test_cases[idx],
				     fu_systemd_pcrlock_plugin_secure_boot_update_func);
	}
	return g_test_run();
}
