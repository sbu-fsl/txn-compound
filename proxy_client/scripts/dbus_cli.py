#!/usr/bin/python
'''NFS-Ganesha Dbus CLI.
Also see support/* and scripts/ganeshactl/*.
'''
import dbus
import datetime

from collections import namedtuple

Export_Columns = ['ExportID',
                'ExportPath',
                'HasNFSv3',
                'HasMNT',
                'HasNLM4',
                'HasRQUOTA',
                'HasNFSv40',
                'HasNFSv41',
                'Has9P',
                'LastTime']

# see server_stats_summary(), export_to_dbus(), and ganeshactl/Ganesha/export_mgr.py
Export = namedtuple('Export', Export_Columns)

bus = dbus.SystemBus()

def parse_timespec(tm):
        tmspec = datetime.datetime.fromtimestamp(tm[0])
        tmspec += datetime.timedelta(microseconds=tm[1]/1000)
        return tmspec.strftime("%x-%X-%f")

def print_exports():
        em = bus.get_object("org.ganesha.nfsd", "/org/ganesha/nfsd/ExportMgr")
        ShowExports = em.get_dbus_method('ShowExports', 'org.ganesha.nfsd.exportmgr')
        print "exports:"
        # see export_mgr.c: export_show_exports for interface
        _, exports = ShowExports()  # ignore the first reply --- timestamp
        print("\t".join(Export_Columns))
        for ex in exports:
                print("%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" %
                      (ex[0],       # ExportID
                       ex[1],       # ExportPath
                       ex[2],       # HasNFSv3
                       ex[3],       # HasMNT
                       ex[4],       # HasNLM4
                       ex[5],       # HasRQUOTA
                       ex[6],       # HasNFSv40
                       ex[7],       # HasNFSv41
                       ex[8],       # Has9P
                       parse_timespec(ex[9])))
        return ex[0]


def print_iostats(stats):
        print("requested\ttransferred\ttotal\terrors\tlatency(ns)\tqueue_latency(ns)")
        print("%d\t\t%d\t\t%d\t%d\t%d\t\t%d" % (stats[0], stats[1], stats[2],
              stats[3], stats[4], stats[5]))


def print_compounds(exp_id):
        # see support/export_mgr.c: server_dbus_v40_iostats
        v40io = bus.get_object("org.ganesha.nfsd",
                               "/org/ganesha/nfsd/ExportMgr")
        GetNFSv40IO = v40io.get_dbus_method('GetNFSv40IO', 'org.ganesha.nfsd.exportstats')
        # see export_mgr.c: export_show_v40_io for interface
        st, err, ts, rd_stats, wr_stats = GetNFSv40IO(exp_id)
        print("===== READ: =====")
        print_iostats(rd_stats)
        print("===== WRITE: =====")
        print_iostats(wr_stats)


if __name__ == '__main__':
        exp_id = print_exports()
        print_compounds(exp_id)

# vim:expandtab:shiftwidth=8:tabstop=8:
