#!/usr/bin/python
'''NFS-Ganesha Dbus CLI.
Also see support/* and scripts/ganeshactl/*.
'''
import dbus

from collections import namedtuple

# see server_stats_summary(), export_to_dbus(), and ganeshactl/Ganesha/export_mgr.py
Export = namedtuple('Export',
                    ['ExportID',
                     'ExportPath',
                     'HasNFSv3',
                     'HasMNT',
                     'HasNLM4',
                     'HasRQUOTA',
                     'HasNFSv40',
                     'HasNFSv41',
                     'Has9P',
                     'LastTime'])

bus = dbus.SystemBus()

em = bus.get_object("org.ganesha.nfsd", "/org/ganesha/nfsd/ExportMgr")
ShowExports = em.get_dbus_method('ShowExports', 'org.ganesha.nfsd.exportmgr')
print "exports:"
ts, exports = ShowExports()
print ts
for ex in exports:
	exp = Export(ExportID = ex[0],
		     ExportPath = ex[1],
		     HasNFSv3 = ex[2],
		     HasMNT = ex[3],
		     HasNLM4 = ex[4],
		     HasRQUOTA = ex[5],
		     HasNFSv40 = ex[6],
		     HasNFSv41 = ex[7],
		     Has9P = ex[8],
		     LastTime = ex[9])
	print exp
