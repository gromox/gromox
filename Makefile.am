# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I build-aux
AM_CPPFLAGS = -I${top_srcdir}/include ${HX_CFLAGS} ${gumbo_CFLAGS} ${crypto_CFLAGS} ${jsoncpp_CFLAGS} ${mysql_CFLAGS} ${sqlite_CFLAGS} ${ssl_CFLAGS} ${zlib_CFLAGS}
AM_CFLAGS = ${my_CFLAGS} -fvisibility=default
AM_CXXFLAGS = ${my_CXXFLAGS}

lib_LTLIBRARIES = libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_epoll.la libgromox_email.la libgromox_mapi.la libgromox_rpc.la
noinst_LTLIBRARIES = libphp_mapi.la
noinst_DATA = libgromox_common.ldd libgromox_epoll.ldd libgromox_email.ldd libgromox_rpc.ldd libgromox_mapi.ldd
pkglibexec_PROGRAMS = ${mta_system} ${mra_system} ${exchange_progs} ${agent_service_progs} ${system_admin_progs} ${system_admin_tools}
pkglib_LTLIBRARIES = ${mta_plugins} ${mra_plugins} ${exchange_plugins}
default_sym = ${srcdir}/default.sym
default_SYFLAGS = -Wl,--version-script=${default_sym}
plugin_LDFLAGS = -avoid-version -module ${default_SYFLAGS${NO_VSYM}}
pamlibdir = ${libdir}/security
if HAVE_PAM
pamlib_LTLIBRARIES = pam_gromox.la
noinst_DATA += pam_gromox.ldd
endif
if HAVE_PHP
phpinidir = ${PHP_SYSCONF_DIR}
phpini_DATA = php_mapi/mapi.ini
phplibdir = ${PHP_EXTENSION_DIR}
phplib_LTLIBRARIES = mapi.la
endif
unit_services = system/gromox-adaptor.service system/gromox-delivery.service system/gromox-event.service system/gromox-http.service system/gromox-imap.service system/gromox-midb.service system/gromox-pop3.service system/gromox-smtp.service system/gromox-timer.service system/gromox-zcore.service
unit_targets = system/gromox-exch.target system/gromox-mra.target system/gromox-mta.target system/gromox-sa.target
unit_DATA = ${unit_services} ${unit_targets}

mta_system = delivery smtp
mta_plugins = \
	libgxf_message_enqueue.la \
	libgxm_alias_translator.la \
	libgxm_exmdb_local.la \
	libgxm_mlist_expand.la \
	libgxs_domain_list.la
noinst_DATA += \
	libgxf_message_enqueue.ldd \
	libgxm_alias_translator.ldd \
	libgxm_exmdb_local.ldd \
	libgxm_mlist_expand.ldd \
	libgxs_domain_list.ldd
mra_system = pop3 imap
mra_plugins = \
	libgxs_event_proxy.la \
	libgxs_event_stub.la \
	libgxs_midb_agent.la
noinst_DATA += \
	libgxs_event_proxy.ldd \
	libgxs_event_stub.ldd \
	libgxs_midb_agent.ldd
exchange_progs = http midb zcore
exchange_plugins = \
	libgxs_codepage_lang.la \
	libgxs_exmdb_provider.la \
	libgxs_timer_agent.la \
	libgxp_exchange_emsmdb.la \
	libgxp_exchange_nsp.la \
	libgxp_exchange_rfr.la \
	libgxh_moh_emsmdb.la libgxh_moh_nsp.la libgxh_proxy.la \
	libgxs_abktplug.la \
	libgxs_at_client.la \
	libgxs_authmgr.la \
	libgxs_ip6_container.la libgxs_ip6_filter.la \
	libgxs_ldap_adaptor.la \
	libgxs_log_plugin.la libgxs_logthru.la \
	libgxs_mysql_adaptor.la \
	libgxs_textmaps.la \
	libgxs_user_filter.la
noinst_DATA += \
	libgxs_codepage_lang.ldd \
	libgxs_exmdb_provider.ldd \
	libgxs_timer_agent.ldd \
	libgxp_exchange_emsmdb.ldd \
	libgxp_exchange_nsp.ldd \
	libgxp_exchange_rfr.ldd \
	libgxh_moh_emsmdb.ldd libgxh_moh_nsp.ldd libgxh_proxy.ldd \
	libgxs_abktplug.ldd \
	libgxs_at_client.ldd \
	libgxs_authmgr.ldd \
	libgxs_ip6_container.ldd libgxs_ip6_filter.ldd \
	libgxs_ldap_adaptor.ldd \
	libgxs_log_plugin.ldd libgxs_logthru.ldd \
	libgxs_mysql_adaptor.ldd \
	libgxs_textmaps.ldd \
	libgxs_user_filter.ldd
agent_service_progs = digest freebusy rtf2html
system_admin_progs = adaptor event timer
system_admin_tools = mkmidb mkprivate mkpublic rebuild
sbin_PROGRAMS = gromox-dbop gromox-mailq
pkglibexec_SCRIPTS = tools/create_queue.sh tools/sa_format_area.sh

BUILT_SOURCES = include/gromox/paths.h php_mapi/zarafa_rpc.cpp exch/midb/exmdb_rpc.cpp exch/zcore/exmdb_rpc.cpp exch/exmdb_provider/exmdb_rpc.cpp
CLEANFILES = ${BUILT_SOURCES}
libgromox_common_la_CXXFLAGS = ${AM_CXXFLAGS} -fvisibility=default
libgromox_common_la_SOURCES = lib/alloc_context.cpp lib/array.cpp lib/config_file.cpp lib/cookie_parser.cpp lib/dir_tree.cpp lib/double_list.cpp lib/errno.cpp lib/files_allocator.cpp lib/fopen.cpp lib/guid.cpp lib/int_hash.cpp lib/lib_buffer.cpp lib/list_file.cpp lib/mail_func.cpp lib/mem_file.cpp lib/rfbl.cpp lib/simple_tree.cpp lib/single_list.cpp lib/socket.cpp lib/str_hash.cpp lib/stream.cpp lib/timezone.cpp lib/util.cpp lib/xarray.cpp
libgromox_common_la_LIBADD = -lcrypt ${HX_LIBS}
libgromox_cplus_la_SOURCES = lib/fileio.cpp lib/fopen.cpp lib/oxoabkt.cpp lib/textmaps.cpp
libgromox_cplus_la_LIBADD = -lpthread ${HX_LIBS} ${jsoncpp_LIBS}
libgromox_dbop_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_dbop_la_SOURCES = lib/dbop_mysql.cpp
libgromox_dbop_la_LIBADD = ${mysql_LIBS}
libgromox_email_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_email_la_SOURCES = lib/email/dsn.cpp lib/email/ical.cpp lib/email/ical2.cpp lib/email/mail.cpp lib/email/mime.cpp lib/email/mime_pool.cpp lib/email/mjson.cpp lib/email/vcard.cpp
libgromox_email_la_LIBADD = ${HX_LIBS} ${ssl_LIBS} libgromox_common.la
libgromox_epoll_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_epoll_la_SOURCES = lib/contexts_pool.cpp lib/threads_pool.cpp
libgromox_epoll_la_LIBADD = -lpthread -lrt libgromox_common.la
libgromox_mapi_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_mapi_la_SOURCES = lib/mapi/apple_util.cpp lib/mapi/applefile.cpp lib/mapi/binhex.cpp lib/mapi/eid_array.cpp lib/mapi/element_data.cpp lib/mapi/ext_buffer.cpp lib/mapi/html.cpp lib/mapi/idset.cpp lib/mapi/macbinary.cpp lib/mapi/oxcical.cpp lib/mapi/oxcmail.cpp lib/mapi/oxvcard.cpp lib/mapi/pcl.cpp lib/mapi/proptag_array.cpp lib/mapi/propval.cpp lib/mapi/restriction.cpp lib/mapi/rop_util.cpp lib/mapi/rtf.cpp lib/mapi/rtfcp.cpp lib/mapi/rule_actions.cpp lib/mapi/sortorder_set.cpp lib/mapi/tarray_set.cpp lib/mapi/tnef.cpp lib/mapi/tpropval_array.cpp
libgromox_mapi_la_LIBADD = ${gumbo_LIBS} ${HX_LIBS} libgromox_common.la libgromox_email.la
libgromox_rpc_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_rpc_la_SOURCES = lib/rpc/arcfour.cpp lib/rpc/crc32.cpp lib/rpc/hmacmd5.cpp lib/rpc/ndr.cpp lib/rpc/ntlmdes.cpp lib/rpc/ntlmssp.cpp
libgromox_rpc_la_LIBADD = ${crypto_LIBS} ${HX_LIBS} libgromox_common.la

delivery_SOURCES = exch/http/service.cpp lib/console_server.cpp mda/delivery_app/console_cmd_handler.cpp mda/delivery_app/main.cpp mda/delivery_app/message_dequeue.cpp mda/delivery_app/system_services.cpp mda/delivery_app/transporter.cpp
delivery_LDADD = -ldl -lpthread ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
smtp_SOURCES = exch/http/blocks_allocator.cpp exch/http/service.cpp lib/console_server.cpp mda/smtp/console_cmd_handler.cpp mda/smtp/flusher.cpp mda/smtp/listener.cpp mda/smtp/main.cpp mda/smtp/resource.cpp mda/smtp/smtp_cmd_handler.cpp mda/smtp/smtp_parser.cpp mda/smtp/system_services.cpp
smtp_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la
libgxf_message_enqueue_la_SOURCES = mda/message_enqueue.cpp
libgxf_message_enqueue_la_LDFLAGS = ${plugin_LDFLAGS}
libgxf_message_enqueue_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxf_message_enqueue_la_DEPENDENCIES = ${default_sym}
libgxm_alias_translator_la_SOURCES = mda/alias_translator.cpp
libgxm_alias_translator_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_alias_translator_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxm_alias_translator_la_DEPENDENCIES = ${default_sym}
libgxm_exmdb_local_la_SOURCES = mda/exmdb_local/auto_response.cpp mda/exmdb_local/bounce_audit.cpp mda/exmdb_local/bounce_producer.cpp mda/exmdb_local/cache_queue.cpp mda/exmdb_local/exmdb_client.cpp mda/exmdb_local/exmdb_local.cpp mda/exmdb_local/main.cpp mda/exmdb_local/net_failure.cpp
libgxm_exmdb_local_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_exmdb_local_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
EXTRA_libgxm_exmdb_local_la_DEPENDENCIES = ${default_sym}
libgxm_mlist_expand_la_SOURCES = mda/mlist_expand/bounce_producer.cpp mda/mlist_expand/main.cpp
libgxm_mlist_expand_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_mlist_expand_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
EXTRA_libgxm_mlist_expand_la_DEPENDENCIES = ${default_sym}
libgxs_domain_list_la_SOURCES = exch/str_table.cpp
libgxs_domain_list_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_domain_list_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_domain_list_la_DEPENDENCIES = ${default_sym}

pop3_SOURCES = exch/http/blocks_allocator.cpp exch/http/service.cpp lib/console_server.cpp mra/pop3/console_cmd_handler.cpp mra/pop3/listener.cpp mra/pop3/main.cpp mra/pop3/pop3_cmd_handler.cpp mra/pop3/pop3_parser.cpp mra/pop3/resource.cpp mra/pop3/system_services.cpp mra/pop3/units_allocator.cpp
pop3_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la
imap_SOURCES = exch/http/blocks_allocator.cpp exch/http/service.cpp lib/console_server.cpp mra/imap/console_cmd_handler.cpp mra/imap/imap_cmd_parser.cpp mra/imap/imap_parser.cpp mra/imap/listener.cpp mra/imap/main.cpp mra/imap/resource.cpp mra/imap/system_services.cpp
imap_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la libgromox_email.la
libgxs_event_proxy_la_SOURCES = mra/event_proxy.cpp
libgxs_event_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_event_proxy_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_event_proxy_la_DEPENDENCIES = ${default_sym}
libgxs_event_stub_la_SOURCES = mra/event_stub.cpp
libgxs_event_stub_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_event_stub_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_event_stub_la_DEPENDENCIES = ${default_sym}
libgxs_midb_agent_la_SOURCES = mra/midb_agent.cpp
libgxs_midb_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_midb_agent_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_midb_agent_la_DEPENDENCIES = ${default_sym}

http_SOURCES = exch/http/blocks_allocator.cpp exch/http/console_cmd_handler.cpp exch/http/hpm_processor.cpp exch/http/http_parser.cpp exch/http/listener.cpp exch/http/main.cpp exch/http/mod_cache.cpp exch/http/mod_fastcgi.cpp exch/http/mod_rewrite.cpp exch/http/pdu_ndr.cpp exch/http/pdu_processor.cpp exch/http/service.cpp exch/http/system_services.cpp lib/console_server.cpp
http_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la libgromox_email.la libgromox_rpc.la libgromox_mapi.la
midb_SOURCES = exch/http/service.cpp exch/midb/cmd_parser.cpp exch/midb/common_util.cpp exch/midb/console_cmd_handler.cpp exch/midb/exmdb_client.cpp exch/midb/exmdb_ext.cpp exch/midb/exmdb_rpc.cpp exch/midb/listener.cpp exch/midb/mail_engine.cpp exch/midb/main.cpp exch/midb/system_services.cpp lib/console_server.cpp
midb_LDADD = -ldl -lpthread -lresolv ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
zcore_SOURCES = exch/http/service.cpp exch/zcore/ab_tree.cpp exch/zcore/attachment_object.cpp exch/zcore/bounce_producer.cpp exch/zcore/common_util.cpp exch/zcore/console_cmd_handler.cpp exch/zcore/container_object.cpp exch/zcore/exmdb_client.cpp exch/zcore/exmdb_ext.cpp exch/zcore/exmdb_rpc.cpp exch/zcore/folder_object.cpp exch/zcore/ics_state.cpp exch/zcore/icsdownctx_object.cpp exch/zcore/icsupctx_object.cpp exch/zcore/listener.cpp exch/zcore/main.cpp exch/zcore/message_object.cpp exch/zcore/msgchg_grouping.cpp exch/zcore/names.cpp exch/zcore/object_tree.cpp exch/zcore/rpc_ext.cpp exch/zcore/rpc_parser.cpp exch/zcore/store_object.cpp exch/zcore/system_services.cpp exch/zcore/table_object.cpp exch/zcore/user_object.cpp exch/zcore/zarafa_server.cpp lib/console_server.cpp
zcore_LDADD = -ldl -lpthread ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
libgxs_codepage_lang_la_SOURCES = exch/codepage_lang.cpp
libgxs_codepage_lang_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_codepage_lang_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_codepage_lang_la_DEPENDENCIES = ${default_sym}
libgxs_exmdb_provider_la_SOURCES = exch/exmdb_provider/bounce_producer.cpp exch/exmdb_provider/common_util.cpp exch/exmdb_provider/db_engine.cpp exch/exmdb_provider/exmdb_client.cpp exch/exmdb_provider/exmdb_ext.cpp exch/exmdb_provider/exmdb_listener.cpp exch/exmdb_provider/exmdb_parser.cpp exch/exmdb_provider/exmdb_rpc.cpp exch/exmdb_provider/notification_agent.cpp exch/exmdb_provider/exmdb_server.cpp exch/exmdb_provider/folder.cpp exch/exmdb_provider/ics.cpp exch/exmdb_provider/instance.cpp exch/exmdb_provider/instbody.cpp exch/exmdb_provider/main.cpp exch/exmdb_provider/message.cpp exch/exmdb_provider/names.cpp exch/exmdb_provider/store.cpp exch/exmdb_provider/table.cpp
libgxs_exmdb_provider_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_exmdb_provider_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
EXTRA_libgxs_exmdb_provider_la_DEPENDENCIES = ${default_sym}
libgxs_timer_agent_la_SOURCES = exch/timer_agent.cpp
libgxs_timer_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_timer_agent_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_timer_agent_la_DEPENDENCIES = ${default_sym}
libgxp_exchange_emsmdb_la_SOURCES = exch/exchange_emsmdb/asyncemsmdb_interface.cpp exch/exchange_emsmdb/asyncemsmdb_ndr.cpp exch/exchange_emsmdb/attachment_object.cpp exch/exchange_emsmdb/aux_ext.cpp exch/exchange_emsmdb/bounce_producer.cpp exch/exchange_emsmdb/common_util.cpp exch/exchange_emsmdb/emsmdb_interface.cpp exch/exchange_emsmdb/emsmdb_ndr.cpp exch/exchange_emsmdb/exmdb_client.cpp exch/exchange_emsmdb/fastdownctx_object.cpp exch/exchange_emsmdb/fastupctx_object.cpp exch/exchange_emsmdb/folder_object.cpp exch/exchange_emsmdb/ftstream_parser.cpp exch/exchange_emsmdb/ftstream_producer.cpp exch/exchange_emsmdb/ics_state.cpp exch/exchange_emsmdb/icsdownctx_object.cpp exch/exchange_emsmdb/icsupctx_object.cpp exch/exchange_emsmdb/logon_object.cpp exch/exchange_emsmdb/main.cpp exch/exchange_emsmdb/message_object.cpp exch/exchange_emsmdb/msgchg_grouping.cpp exch/exchange_emsmdb/names.c exch/exchange_emsmdb/notify_response.cpp exch/exchange_emsmdb/oxcfold.cpp exch/exchange_emsmdb/oxcfxics.cpp exch/exchange_emsmdb/oxcmsg.cpp exch/exchange_emsmdb/oxcnotif.cpp exch/exchange_emsmdb/oxcperm.cpp exch/exchange_emsmdb/oxcprpt.cpp exch/exchange_emsmdb/oxcstore.cpp exch/exchange_emsmdb/oxctabl.cpp exch/exchange_emsmdb/oxomsg.cpp exch/exchange_emsmdb/oxorule.cpp exch/exchange_emsmdb/rop_dispatch.cpp exch/exchange_emsmdb/rop_ext.cpp exch/exchange_emsmdb/rop_processor.cpp exch/exchange_emsmdb/stream_object.cpp exch/exchange_emsmdb/subscription_object.cpp exch/exchange_emsmdb/table_object.cpp lib/mapi/lzxpress.cpp
libgxp_exchange_emsmdb_la_LDFLAGS = ${plugin_LDFLAGS}
libgxp_exchange_emsmdb_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_rpc.la
EXTRA_libgxp_exchange_emsmdb_la_DEPENDENCIES = ${default_sym}
libgxp_exchange_nsp_la_SOURCES = exch/exchange_nsp/ab_tree.cpp exch/exchange_nsp/common_util.cpp exch/exchange_nsp/main.cpp exch/exchange_nsp/nsp_interface.cpp exch/exchange_nsp/nsp_ndr.cpp
libgxp_exchange_nsp_la_LDFLAGS = ${plugin_LDFLAGS}
libgxp_exchange_nsp_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} libgromox_common.la libgromox_rpc.la
EXTRA_libgxp_exchange_nsp_la_DEPENDENCIES = ${default_sym}
libgxp_exchange_rfr_la_SOURCES = exch/exchange_rfr.cpp
libgxp_exchange_rfr_la_LDFLAGS = ${plugin_LDFLAGS}
libgxp_exchange_rfr_la_LIBADD = ${HX_LIBS} libgromox_common.la libgromox_rpc.la
EXTRA_libgxp_exchange_rfr_la_DEPENDENCIES = ${default_sym}
libgxh_moh_emsmdb_la_SOURCES = exch/moh_emsmdb/emsmdb_bridge.cpp exch/moh_emsmdb/main.cpp exch/moh_emsmdb/mb_ext.cpp
libgxh_moh_emsmdb_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_moh_emsmdb_la_LIBADD = -lpthread libgromox_common.la libgromox_mapi.la
EXTRA_libgxh_moh_emsmdb_la_DEPENDENCIES = ${default_sym}
libgxh_moh_nsp_la_SOURCES = exch/moh_nsp/ab_ext.cpp exch/moh_nsp/common_util.cpp exch/moh_nsp/main.cpp exch/moh_nsp/nsp_bridge.cpp
libgxh_moh_nsp_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_moh_nsp_la_LIBADD = libgromox_common.la libgromox_mapi.la
EXTRA_libgxh_moh_nsp_la_DEPENDENCIES = ${default_sym}
libgxh_proxy_la_SOURCES = exch/mod_proxy.cpp
libgxh_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_proxy_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libgxh_proxy_la_DEPENDENCIES = ${default_sym}
libgxs_abktplug_la_SOURCES = exch/abktplug.cpp
libgxs_abktplug_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_abktplug_la_LIBADD = libgromox_cplus.la
EXTRA_libgxs_abktplug_la_DEPENDENCIES = ${default_sym}
libgxs_at_client_la_SOURCES = exch/at_client.cpp
libgxs_at_client_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_at_client_la_LIBADD = ${HX_LIBS}
EXTRA_libgxs_at_client_la_DEPENDENCIES = ${default_sym}
libgxs_authmgr_la_SOURCES = exch/authmgr.cpp
libgxs_authmgr_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_authmgr_la_LIBADD = libgromox_common.la
EXTRA_libgxs_authmgr_la_DEPENDENCIES = ${default_sym}
libgxs_ip6_container_la_SOURCES = exch/ip6_container.cpp
libgxs_ip6_container_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_ip6_container_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libgxs_ip6_container_la_DEPENDENCIES = ${default_sym}
libgxs_ip6_filter_la_SOURCES = exch/ip6_filter.cpp
libgxs_ip6_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_ip6_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_ip6_filter_la_DEPENDENCIES = ${default_sym}
libgxs_ldap_adaptor_la_SOURCES = exch/ldap_adaptor.cpp
libgxs_ldap_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_ldap_adaptor_la_LIBADD = libgromox_common.la -lldap_r
EXTRA_libgxs_ldap_adaptor_la_DEPENDENCIES = ${default_sym}
libgxs_log_plugin_la_SOURCES = exch/log_plugin.cpp
libgxs_log_plugin_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_log_plugin_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_log_plugin_la_DEPENDENCIES = ${default_sym}
libgxs_logthru_la_SOURCES = exch/logthru.cpp
libgxs_logthru_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_logthru_la_LIBADD = libgromox_common.la
EXTRA_libgxs_logthru_la_DEPENDENCIES = ${default_sym}
libgxs_mysql_adaptor_la_SOURCES = exch/mysql_adaptor/main.cpp exch/mysql_adaptor/mysql_adaptor.cpp exch/mysql_adaptor/sql2.cpp
libgxs_mysql_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_mysql_adaptor_la_LIBADD = -lcrypt -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_dbop.la
EXTRA_libgxs_mysql_adaptor_la_DEPENDENCIES = ${default_sym}
libgxs_textmaps_la_SOURCES = exch/textmapplug.cpp
libgxs_textmaps_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_textmaps_la_LIBADD = ${HX_LIBS} libgromox_cplus.la
EXTRA_libgxs_textmaps_la_DEPENDENCIES = ${default_sym}
libgxs_user_filter_la_SOURCES = exch/str_filter/audit_filter.cpp exch/str_filter/grey_list.cpp exch/str_filter/main.cpp exch/str_filter/str_filter.cpp exch/str_filter/temp_list.cpp
libgxs_user_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_user_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_user_filter_la_DEPENDENCIES = ${default_sym}

digest_SOURCES = tools/digest.cpp
digest_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la
freebusy_SOURCES = tools/freebusy.cpp
freebusy_LDADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
pam_gromox_la_CPPFLAGS = ${AM_CPPFLAGS}
pam_gromox_la_SOURCES = tools/pam_gromox.cpp exch/http/service.cpp
pam_gromox_la_LIBADD = -lpam ${HX_LIBS} libgromox_common.la
pam_gromox_la_LDFLAGS = -avoid-version -module ${plugin_LDFLAGS}
rtf2html_SOURCES = tools/rtf2html.cpp
rtf2html_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
saphpdir = ${pkgdatadir}/sa
saphp_DATA = tools/php/conf.php tools/php/db.php tools/php/submit.php
adaptor_SOURCES = lib/system_log.cpp tools/adaptor/data_source.cpp tools/adaptor/engine.cpp tools/adaptor/file_operation.cpp tools/adaptor/gateway_control.cpp tools/adaptor/main.cpp
adaptor_LDADD = -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la
event_SOURCES = tools/event.cpp lib/fifo.cpp
event_LDADD = -lpthread -lrt ${HX_LIBS} libgromox_common.la
gromox_dbop_SOURCES = lib/dbop_mysql.cpp tools/dbop_main.cpp
gromox_dbop_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_dbop.la
gromox_mailq_SOURCES = tools/mailq.cpp
mkmidb_SOURCES = tools/mkmidb.cpp
mkmidb_LDADD = ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la
mkprivate_SOURCES = tools/mkprivate.cpp
mkprivate_LDADD = ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
mkpublic_SOURCES = tools/mkpublic.cpp
mkpublic_LDADD = ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
rebuild_SOURCES = tools/rebuild.cpp
rebuild_LDADD = ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
timer_SOURCES = tools/timer.cpp
timer_LDADD = -lpthread ${HX_LIBS} libgromox_common.la

libphp_mapi_la_CPPFLAGS = ${AM_CPPFLAGS} ${PHP_INCLUDES}
libphp_mapi_la_SOURCES = php_mapi/ext_pack.cpp php_mapi/mapi.cpp php_mapi/rpc_ext.cpp php_mapi/type_conversion.cpp php_mapi/zarafa_client.cpp php_mapi/zarafa_rpc.cpp
libphp_mapi_la_LIBADD = ${HX_LIBS} libgromox_common.la
mapi_la_SOURCES =
mapi_la_LDFLAGS = ${plugin_LDFLAGS} ${PHP_LDFLAGS}
mapi_la_LIBADD = libphp_mapi.la
EXTRA_mapi_la_DEPENDENCIES = ${default_sym}

noinst_PROGRAMS = tests/abktconv tests/bodyconv tests/icalparse tests/zendfake
tests_abktconv_SOURCES = tests/abktconv.cpp
tests_abktconv_LDADD = ${HX_LIBS} libgromox_cplus.la
tests_bodyconv_SOURCES = tests/bodyconv.cpp
tests_bodyconv_LDADD = libgromox_common.la libgromox_mapi.la
tests_icalparse_SOURCES = tests/icalparse.cpp
tests_icalparse_LDADD = libgromox_common.la libgromox_email.la libgromox_mapi.la
tests_zendfake_LDADD = libphp_mapi.la

man_MANS = \
	doc/adaptor.8gx doc/alias_translator.4gx doc/at_client.4gx \
	doc/authmgr.4gx doc/autodiscover.4gx doc/delivery.8gx \
	doc/digest.8gx doc/domain_list.4gx \
	doc/event.8gx doc/event_stub.4gx doc/event_proxy.4gx \
	doc/exchange_emsmdb.4gx \
	doc/exchange_nsp.4gx doc/exchange_rfr.4gx \
	doc/exmdb_local.4gx doc/exmdb_provider.4gx \
	doc/freebusy.8gx doc/gromox.7 \
	doc/gromox-dbop.8gx \
	doc/gromox-exch.target.8gx doc/gromox-mailq.8gx \
	doc/gromox-mra.target.8gx doc/gromox-mta.target.8gx \
	doc/gromox-sa.target.8gx doc/http.8gx \
	doc/imap.8gx doc/ip6_container.4gx doc/ldap_adaptor.4gx \
	doc/log_plugin.4gx doc/logthru.4gx \
	doc/mapi.4gx doc/message_enqueue.4gx doc/midb.8gx doc/midb_agent.4gx \
	doc/mkmidb.8gx doc/mkprivate.8gx doc/mkpublic.8gx \
	doc/mod_cache.4gx doc/mod_fastcgi.4gx doc/mod_proxy.4gx doc/mod_rewrite.4gx \
	doc/moh_emsmdb.4gx doc/moh_nsp.4gx doc/mysql_adaptor.4gx \
	doc/pam_gromox.8gx doc/pop3.8gx doc/rebuild.8gx \
	doc/rtf2html.1gx doc/sa.cfg.5gx doc/smtp.8gx \
	doc/str_filter.4gx doc/str_table.4gx doc/textmaps.4gx \
	doc/timer.8gx doc/timer_agent.4gx doc/zcore.8gx

include/gromox/paths.h: include/gromox/paths.h.in ${top_builddir}/config.status
	${AM_V_GEN}sed -e 's|#define PKGSYSCONFDIR .*|#define PKGSYSCONFDIR "${sysconfdir}/${PACKAGE_NAME}"|' \
	 -e 's|#define PKGLIBDIR .*|#define PKGLIBDIR "${pkglibdir}"|' \
	 -e 's|#define PKGDATADIR .*|#define PKGDATADIR "${pkgdatadir}"|' \
	 -e 's|#define PKGSTATEDIR .*|#define PKGSTATEDIR "${localstatedir}/lib/${PACKAGE_NAME}"|' \
	 -e 's|#define PKGLOGDIR .*|#define PKGLOGDIR "${localstatedir}/log/${PACKAGE_NAME}"|' \
		<$< >$@.tmp
	${AM_V_at}if ! cmp $@ $@.tmp 2>/dev/null; then mv $@.tmp $@; fi; rm -f $@.tmp

php_mapi/zarafa_rpc.cpp: php_mapi/zarafa_client.h zcidl
	${AM_V_GEN}${top_srcdir}/zcidl <$< >$@

exch/midb/exmdb_rpc.cpp: exch/midb/exmdb_client.h exmidl
	${AM_V_GEN}${top_srcdir}/exmidl <$< >$@

exch/zcore/exmdb_rpc.cpp: exch/zcore/exmdb_client.h exmidl
	${AM_V_GEN}${top_srcdir}/exmidl <$< >$@

exch/exmdb_provider/exmdb_rpc.cpp: exch/exmdb_provider/exmdb_client.h exmidl
	${AM_V_GEN}${top_srcdir}/exmidl -p <$< >$@

install-data-local:
	${MKDIR_P} ${DESTDIR}${pkgdatadir}/http/php
	cp -av data/* ${DESTDIR}${pkgdatadir}/
	cp -av exch/php/* ${DESTDIR}${pkgdatadir}/http/php/

.la.ldd:
	${AM_V_GEN}${top_srcdir}/lddcheck ${top_builddir}/libtool $< $@
%.service: ${top_builddir}/config.status
.tps.service:
	${AM_V_GEN}${SED} -e 's|@''libexecdir''@|${libexecdir}|g' <$< >$@

.PHONY: tarball
tarball:
	tmpdir=$$(mktemp -dtu); \
	mkdir $$tmpdir && \
	pushd ${top_srcdir} && git archive --prefix=${PACKAGE_NAME}-${PACKAGE_VERSION}/ HEAD | tar -C $$tmpdir -x && popd; \
	pushd $$tmpdir/${PACKAGE_NAME}-${PACKAGE_VERSION} && autoreconf -fi && popd; \
	tar --use=zstd -C $$tmpdir -cf ${PACKAGE_NAME}-${PACKAGE_VERSION}.tar.zst --owner=root --group=root ${PACKAGE_NAME}-${PACKAGE_VERSION}/; \
	rm -Rf $$tmpdir
