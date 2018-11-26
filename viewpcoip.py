'''
Created on 12/08/2014
@author: Jinxin Ying, Ma Yuan, Xiaolong Shi
'''

from __future__ import nested_scopes, generators, division, absolute_import, with_statement, print_function, unicode_literals

import sys, os, stat
import codecs
import time
import string
import re
import datetime
import traceback
import platform

PROJ_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
if not PROJ_ROOT in sys.path:
    sys.path.append(PROJ_ROOT)

MODULE_ROOT = os.path.join(PROJ_ROOT, 'vcdt', 'scripts', 'viewpcoip')
if not MODULE_ROOT in sys.path:
    sys.path.append(MODULE_ROOT)
import vcdtlib
import parser_session_agent
import parser_session_broker
import parser_session_client
import parser_highlight
from parser_system_info import *
from parser_security_server import *
from parser_perf import *
from helper import *

__PCOIP_DEBUG__ = False
def PCOIP_DEBUG_LOG(debugstr):
    if __PCOIP_DEBUG__:
        print(debugstr, file=sys.stderr)

# Define the log files we need
REQUIRED_FILES = {
    'coredump':r'.*\.dmp',
    'wsnm_starts':r'wsnm_starts\.txt',
    'wsdiag':r'ws_diag\.txt',
    'vdm-sdct-ver':r'vdm-sdct-ver\.txt',
    'vdm-sdct':r'vdm-sdct\.log',
    'vmware-reg':r'vmware-reg\.txt',
    'sysinfo':r'systeminfo\.txt',
    'pcoipclient':r'pcoip_client_\d{4}_\d{2}_\d{2}_[0-9A-Fa-f]+\.txt',
    'mkslog':r'vmware-mks-\d+\.log',
    'viewclient':r'vdm-logs[\\/](?!All Users).+[\\/]vmware-horizon-viewclient-\d{4}-\d{2}-\d{2}-\d{6}\.txt',
    'user_debuglog':r'vdm-logs[\\/](?!All Users|vmware-SYSTEM).+[\\/]debug-\d{4}-\d{2}-\d{2}-\d{6}\.txt',
    'user_log':r'vdm-logs[\\/](?!CurrentUser|All Users|vmware-SYSTEM).+[\\/]log-\d{4}-\d{2}-\d{2}\.txt',
    'debuglog':r'debug-\d{4}-\d{2}-\d{2}-\d{6}\.txt',
    'log':r'log-\d{4}-\d{2}-\d{2}\.txt',
    'pcoipserver':r'pcoip_server_\d{4}_\d{2}_\d{2}_(\d*_)?[0-9A-Fa-f]+\.txt',
    'pcoipagent':r'pcoip_agent_\d{4}_\d\d_\d\d_.{8}\.txt',
    'psg':r'SecurityGateway_\d{8}_\d{2}-\d{2}-\d{2}_\d*\.log',
    }

class Script(vcdtlib.script.ScriptInfo):
    def __init__(self):
        self.SetInfo(
            name='viewpcoip',
            longName='View PCoIP',
            desc='View PCoIP Network Performance and Connection Session.',
            logTypeNames='view-support-bundle'.split(),
            outFile='out_viewpcoip.html',
            tlFile='tl_viewpcoip.html',
            authors=[('Jinxin Ying', 'jying@vmware.com'), ('Ma Yuan', 'myuan@vmware.com'), ('Xiaolong Shi', 'xiaolongs@vmware.com')],
            isNew=True,
            )

    def Execute(self):
        brokerbundles = []
        clientbundles = []
        agentbundles = []
        brokerssbundles = []
        perfbundles = []

        brokerSessions = []
        agentSessions = []
        clientSessions = []
        sessions = None
        allSessions = {}
        print('Platform: %s %s %s' % (platform.platform(), platform.version(), platform.processor()), file=sys.stderr)
        print('Python Version: %s' % (sys.version), file=sys.stderr)
        # Parse and verify the arguments
        args = vcdtlib.argutils.ParseGenericArgs()
        if not args:
            return

        # Below var for analyzer performance STAT#
        STAT_SYSINFO = datetime.timedelta(0, 0, 0)
        STAT_SESSION = datetime.timedelta(0, 0, 0)
        STAT_SESSION_AGENT = datetime.timedelta(0, 0, 0)
        STAT_SESSION_BROKER = datetime.timedelta(0, 0, 0)
        STAT_SESSION_CLIENT = datetime.timedelta(0, 0, 0)
        STAT_PERF = datetime.timedelta(0, 0, 0)
        STAT_ERROR = datetime.timedelta(0, 0, 0)

        # Find and extract all required files.
        bundles = vcdtlib.fileutils.FindFilesAndBundles(args, REQUIRED_FILES)
        if not bundles:
            self.error = 'Requires View logs.'
            print('Error: Requires View logs.', file=sys.stderr)
            return

        # Parse files
        for bundle in bundles:
            try:
                bundle.version = None
                bundle.type = None
                sessions = []
                bundle.highlightfiles = []
                print('%s Processing %s' % (datetime.datetime.now().__str__(), bundle.name), file=sys.stderr)
                logbundle = LogBundle(bundle, args)
                bundle.type = logbundle.GetBundleType()
                bundle.version = logbundle.GetVersion()
                try:
                    # Register Parser
                    logbundle.RegisterParser('systeminfo', SystemInformationParser())
                    if bundle.type == 'Agent':
                        logbundle.RegisterParser('perfdata', PerformanceDataParser())
                    elif bundle.type == 'Client':
                        None
                    elif bundle.type == 'Broker':
                        brokerssbundles.append(bundle)
                    elif bundle.type == 'Security Server':
                        brokerssbundles.append(bundle)
                        logbundle.RegisterParser('securityserver', SecurityServerParser())
                    elif bundle.type == 'Broker/Security Server':
                        brokerssbundles.append(bundle)
                        logbundle.RegisterParser('securityserver', SecurityServerParser())
                except Exception as e:
                    print('   Error: %s' % (e), file=sys.stderr)
                    print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)

                try:
                    logbundle.ProcessAllFiles()
                    logbundle.BuildResult()
                except Exception as e:
                    print('   Error: %s' % (e), file=sys.stderr)
                    print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)

                # Time zone change information
                timezone = (0, 0)
                try:
                    bundle.timezone = []
                    for timezone in logbundle.TimeZoneMap:
                        bundle.timezone.append((FormatTimeStamp(timezone[0]).encode('ascii'), FormatUTC2LocalTimeStamp(timezone[0], timezone[1]).encode('ascii')))
                    print('   Info: Bundle time zone info %s' % (bundle.timezone), file=sys.stderr)
                except Exception as e:
                    print('   Error: %s' % (e), file=sys.stderr)
                    print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)

                try:
                    # System Information Parser
                    parser = logbundle.GetParser('systeminfo')
                    if parser:
                        bundle.sysinfo = []
                        fileparser = parser.GetFileParser('sysinfo')
                        if fileparser:
                            for name in sorted(fileparser.sysinfo.iterkeys()):
                                bundle.sysinfo.append((name, fileparser.sysinfo[name]))
                        fileparser = parser.GetFileParser('debuglog')
                        if fileparser:
                            bundle.cpu = [(x[0] + timezone[1], x[1]) for x in fileparser.cpu ]
                            bundle.memory = [(x[0] + timezone[1], x[1]) for x in fileparser.memory ]
                            vcdtlib.utils.PrintOutputToHtml('viewpcoip_utilization_%d.html' % (bundle.index), 'tl_viewpcoip_utilization.html', {'bundle': bundle})
                        fileparser = parser.GetFileParser('wsnm_starts')
                        if fileparser:
                            if len(fileparser.wsnm_status) > 0:
                                bundle.wsnm_status = [(x[0] + timezone[1], x[1]) for x in fileparser.wsnm_status ]
                                bundle.wsnm_status.append((logbundle.GetLogEndTime(), fileparser.wsnm_status[-1][1]))
                                vcdtlib.utils.PrintOutputToHtml('viewpcoip_wsnm_%d.html' % (bundle.index), 'tl_viewpcoip_wsnm.html', {'bundle': bundle})
                        bundle.dumps = []
                        fileparser = parser.GetFileParser('coredump')
                        if fileparser:
                            if len(fileparser.dumps) > 0:
                                for dump in fileparser.dumps:
                                    timestamp = dump[0] - timezone[1]
                                    tzp = logbundle.GetTimeZonePair(timestamp)
                                    bundle.dumps.append((FormatUTC2LocalTimeStamp(timestamp, tzp[1]), dump[1], dump[2], dump[3]))
                        bundle.dumps.sort(key=lambda x:x[0])
                except Exception as e:
                    print('   Error: %s' % (e), file=sys.stderr)
                    print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)

                # Security Server
                if bundle.type == 'Security Server' or bundle.type == 'Broker/Security Server':
                    try:
                        parser = logbundle.GetParser('securityserver')
                        if parser:
                            bundle.psg_connections = []
                            bundle.psg_highwatermark = []
                            bundle.psg_service_status = []
                            fileparser = parser.GetFileParser('psg')
                            if fileparser:
                                bundle.psg_connections = [(x[0] + timezone[1], x[1]) for x in fileparser.Connections ]
                                bundle.psg_highwatermark = [(x[0] + timezone[1], x[1]) for x in fileparser.HighWaterMarks ]
                                bundle.psg_service_status = [(x[0] + timezone[1], x[1]) for x in fileparser.ServiceStatus ]
                                vcdtlib.utils.PrintOutputToHtml('viewpcoip_psg_users_%d.html' % (bundle.index), 'tl_viewpcoip_psg_users.html', {'bundle': bundle})
                                vcdtlib.utils.PrintOutputToHtml('viewpcoip_psg_status_%d.html' % (bundle.index), 'tl_viewpcoip_psg_status.html', {'bundle': bundle})
                    except Exception as e:
                        print('   Error: %s' % (e), file=sys.stderr)
                        print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)

                # Agent
                if bundle.type == 'Agent':
                    print ("Processing bundle type = Agent", file=sys.stderr)
                    # Performance Data
                    try:
                        parser = logbundle.GetParser('perfdata')
                        print ("Executed get parser for perfdata", file=sys.stderr)
                        if parser:
                            bundle.pcoipserver = []
                            fileparser = parser.GetFileParser('pcoipserver')
                            if fileparser:
                                if len(fileparser.Results) > 0:
                                    for perfdata in fileparser.Results:
                                        print("================perfdata==============\n", perfdata, file=sys.stderr)
                                        afile = perfdata[5]
                                        idx = afile.find(bundle.name)
                                        afilepart = afile[idx:]
                                        htmlfile = afilepart.replace('\\', '_').replace('/', '_') + '.html'
                                        Pid = int(afile[afile.rindex('_') + 1:afile.rindex('.')], 16)
                                        bundle.pcoipserver.append([0, perfdata[0], perfdata[1], perfdata[2], Pid, afile[afile.index(bundle.name):],
                                                                   perfdata[3]['PCoIP Bandwidth Utilization'][2],
                                                                   perfdata[3]['PCoIP Bandwidth Rate Limiting'][2],
                                                                   perfdata[3]['PCoIP Connection Quality'][2],
                                                                   perfdata[3]['PCoIP Packet Counts'][2],
                                                                   perfdata[3]['PCoIP Connection Latency'][2],
                                                                   perfdata[3]['PCoIP Encoder Stats'][2],
                                                                   perfdata[3]['PCoIP Encoder Stats - Changed Pixels'][2],
                                                                   perfdata[3]['PCoIP Encoder Stats - Delta Bits'][2],
                                                                   perfdata[3]['PCoIP Encoder Stats - Encoder Performance'][2],
                                                                   perfdata[3]['PCoIP Encoder Stats - Client Performance'][2],
                                                                   perfdata[4]['Server'],
                                                                   perfdata[4]['Network'],
                                                                   perfdata[4]['Options'],
                                                                   perfdata[4]['Displays'],
                                                                   htmlfile
                                                                   ])
                                    if bundle.pcoipserver:
                                        idx = 1
                                        for item in bundle.pcoipserver:
                                            print("item in bundle.pcoipserver is", item, file=sys.stderr)
                                            item[0] = idx
                                            # Print output
                                            data = {'bundle': bundle, 'index':item[0], 'starttime':item[1], 'endtime':item[2], 'file':item[5],
                                                    'utilization':item[6],
                                                    'rate_limiting':item[7],
                                                    'connection_quality':item[8],
                                                    'packet_counts':item[9],
                                                    'connection_latency':item[10],
                                                    'encoder_stats':item[11],
                                                    'encoder_stats_pixels':item[12],
                                                    'encoder_stats_bits':item[13],
                                                    'encoder_stats_perf':item[14],
                                                    'encoder_stats_client':item[15],
                                                    'properties_server':item[16],
                                                    'properties_network':item[17],
                                                    'properties_options':item[18],
                                                    'properties_displays':item[19]
                                                    }
                                            vcdtlib.utils.PrintOutputToHtml('perfdata_' + bundle.name + '.' + str(item[0]) + '.html', 'tl_viewpcoip_perf.html', data)
                                            idx += 1
                                        perfbundles.append(bundle)
                    except Exception as e:
                        print('   Error: %s' % (e), file=sys.stderr)
                        print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)

                ###############################

                STAT_START = datetime.datetime.now()
                print('%s View Logs Connection Session Parser: processing %s' % (datetime.datetime.now().__str__(), bundle.name), file=sys.stderr)
                if bundle.type == 'Agent':
                    try:
                        sessions = parser_session_agent.parser_agent_sessions(logbundle)
                        print("All sessions collected", sessions, file=sys.stderr)
                        if sessions is not None:
                            agentbundles.append(bundle)
                            agentSessions += sessions
                        STAT_END = datetime.datetime.now()
                        STAT_SESSION += STAT_END - STAT_START
                        STAT_SESSION_AGENT += STAT_END - STAT_START
                    except Exception as e:
                        print('   Error: %s' % (e), file=sys.stderr)
                        print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)
                elif bundle.type == 'Broker':
                    try:
                        # sessions = parser_session_broker.parser_broker_sessions(bundle)
                        # if sessions is not None:
                        #    brokerbundles.append(bundle)
                        #    brokerSessions += sessions
                        print('   Warning: Sorry, we don\'t support broker session analysis', file=sys.stderr)
                        STAT_END = datetime.datetime.now()
                        STAT_SESSION += STAT_END - STAT_START
                        STAT_SESSION_BROKER += STAT_END - STAT_START
                    except Exception as e:
                        print('   Error: %s' % (e), file=sys.stderr)
                        print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)
                elif bundle.type == 'Client':
                    try:
                        sessions = parser_session_client.parser_client_sessions(logbundle)
                        if sessions is not None:
                            clientbundles.append(bundle)
                            clientSessions += sessions
                        STAT_END = datetime.datetime.now()
                        STAT_SESSION += STAT_END - STAT_START
                        STAT_SESSION_CLIENT += STAT_END - STAT_START
                    except Exception as e:
                        print('   Error: %s' % (e), file=sys.stderr)
                        print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)

                STAT_START = datetime.datetime.now()
                try:
                    files = {}
                    for session in sessions:
                        for activity in session['Activities']:
                            for log in activity[5]:
                                if log[1] not in files:
                                    files[log[1]] = {}
                                files[log[1]][log[2]] = log[0]
                    logbundle.highlightfiles = []
                    ProcessErrorHighlighting(logbundle, files)
                    bundle.highlightfiles = logbundle.highlightfiles
                except Exception as e:
                    print('   Error: %s' % (e), file=sys.stderr)
                    print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)
                STAT_ERROR += datetime.datetime.now() - STAT_START


            except Exception as e:
                print('   Error: %s' % (e), file=sys.stderr)
                print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)

        STAT_START = datetime.datetime.now()
        # Build sessions connection
        print('Info: Linking the sessions ... ', file=sys.stderr)
        try:
            allSessions = BuildSessions(clientSessions, brokerSessions, agentSessions)
        except Exception as e:
            print('   Error: %s' % (e), file=sys.stderr)
            print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)
        STAT_SESSION += datetime.datetime.now() - STAT_START

        bundles.sort(key=lambda x:x.type)
        brokerssbundles.sort(key=lambda x:x.type)
        # Print output
        data = {'script':self,
                'bundles': bundles,
                'agentbundles': agentbundles,
                'brokerbundles': brokerbundles,
                'clientbundles': clientbundles,
                'brokerssbundles': brokerssbundles,
                'perfbundles': perfbundles,
                'sessions': allSessions}
        vcdtlib.utils.PrintOutputToHtml(self.outFile, self.tlFile, data)

        # Output analyzer perf info
        print('\nTools Performance Statistics: Total TimeCost %s\n   System Information Parser %s\n   Network Performance Parser %s\n   Error Hightlight Parser %s\n   Connection Session Parser %s\n   - Agent Parser %s\n   - Broker Parser %s\n   - Client Parser %s\n'
              % ((STAT_SYSINFO + STAT_PERF + STAT_ERROR + STAT_SESSION).__str__(),
                STAT_SYSINFO.__str__(), STAT_PERF.__str__(), STAT_ERROR.__str__(), STAT_SESSION.__str__(),
                STAT_SESSION_AGENT.__str__(), STAT_SESSION_BROKER.__str__(), STAT_SESSION_CLIENT.__str__()), file=sys.stderr)

def mergeactivities(session):
   activities = {}
   i = 0
   for a in session['Activities']:
      # print (a[3])
      if a[3] not in activities.keys():
         activities[a[3]] = [1, i]
      else:
         activities[a[3]][0] += 1
         activities[a[3]].append(i)
      i += 1
   dlist = []
   for a in activities.keys():
      if activities[a][0] >= 2:
         dlist.extend(activities[a][2:])
         a1 = activities[a][1]
         for item in activities[a][2:]:
            session['Activities'][a1][5] += session['Activities'][item][5]
            session['Activities'][a1][4] = session['Activities'][item][4] if session['Activities'][item][4] > session['Activities'][a1][4] else session['Activities'][a1][4]
   dlist.sort(reverse=True)

   # session['OverallStatus'] = session['Activities'][a1][4] if session['Activities'][a1][4] > session['OverallStatus'] else session['OverallStatus']
   for i in dlist:
      del session['Activities'][i]
   return session

def mergesession(s1, s2, s1_type, s2_type):
   if s1 == None:
      return s2
   if s2 == None:
      return s1

   if s2['StartTime'] != -1 and s2['StartTime'] < s1['StartTime']:
      s1['StartTime'] = s2['StartTime']
   if s2['EndTime'] != -1 and s2['EndTime'] > s1['EndTime']:
      s1['EndTime'] = s2['EndTime']
   s1['Activities'] = s1['Activities'] + s2['Activities']  # pcoip agent log is earlier than pcoip server log if the log time are the same
   if s1_type == 'agent' and s2_type == 'client':
      s1['HasAgentLog'] = True
      s1['HasClientLog'] = True
      if 'Info' in s2:
         s1['ClientInfo'] = s2['Info']
      if 'Warning' in s2:
         s1['ClientWarning'] = s2['Warning']
      if 'Error' in s2:
         s1['ClientError'] = s2['Error']
      if 'DisconnectionCode' in s2:
         s1['ClientDisconnectionCode'] = s2['DisconnectionCode']

   s1['Bundle'] = s1['Bundle'] + "*" + s2['Bundle']
   s1['Activities'].sort()

   s1 = mergeactivities(s1)

   return s1

def combinesessions(clientSessions, brokerSessions, agentSessions):
    combinedsessions = []
    # combine client session with agent sessions
    # print("clientSession num + " + str(len(clientSessions)))
    # print("agentSession num + " + str(len(agentSessions)))
    # for csession in clientSessions:
    #    for asession in agentSessions:
    #        csession = mergesession(csession, asession)
    clientDic = {}
    i = 0
    for csession in clientSessions:
        clientDic[csession['ClientTicketID']] = i
        i += 1
    dlist = []
    for asession in agentSessions:
        key = asession['ClientTicketID']
        if key != "" and key in clientDic.keys():
            cindex = clientDic[key]
            asession = mergesession(asession, clientSessions[cindex], 'agent', 'client')
            dlist.append(cindex)
    dlist = list(set(dlist))
    dlist.sort(reverse=True)

    # print(dlist)
    # print(len(clientSessions))
    for i in dlist:
        del clientSessions[i]

    return (clientSessions, brokerSessions, agentSessions)

def BuildSessions(clientSessions, brokerSessions, agentSessions):
    sessions = {'errors':[], 'warnings':[], 'ok':[], 'preload':[]}
    # combinedsessions = combinesessions(clientSessions, brokerSessions, agentSessions)
    clientSessions, brokerSessions, agentSessions = combinesessions(clientSessions, brokerSessions, agentSessions)

    for c_sess in agentSessions:
        point2self = 0
        session = {}
        session['PreloadSession'] = c_sess['PreloadSession']
        session['HasAgentLog'] = c_sess['HasAgentLog']
        session['HasBrokerLog'] = c_sess['HasBrokerLog']
        session['HasClientLog'] = c_sess['HasClientLog']
        session['StartTime'] = Convert2TimeStr(c_sess['StartTime'])
        session['EndTime'] = Convert2TimeStr(c_sess['EndTime'])
        session['Duration'] = datetime.timedelta(0, int((c_sess['EndTime'] - c_sess['StartTime']) / 1000), 0).__str__()
        session['Bundles'] = []
        tmpbundles = c_sess['Bundle']
        session['Activities'] = []
        for activity in c_sess['Activities']:
            logs = []
            bundlename = tmpbundles.split("*")
            session['Bundles'] = bundlename
            for log in activity[5]:
                # print(log[1])
                afile = log[1]
                for bund in bundlename:
                    idx = afile.find(bund)
                    if idx != -1:
                        break
                # idx = afile.find(bundlename)
                # print(idx)
                if idx:
                    afile = afile[idx:]
                # print(afile)
                htmlfile = afile.replace('\\', '_').replace('/', '_') + '.html'
                # print(htmlfile)
                logs.append((log[0], afile, log[2], Convert2TimeStr(log[3]), log[4], htmlfile))
            session['Activities'].append((activity[0], activity[1], activity[2], activity[3], activity[4], logs))
            if activity[1] == activity[2]:
                point2self += 1

        if 'Info' in c_sess:
            session['AgentInfo'] = c_sess['Info']
        if 'Warning' in c_sess:
            session['AgentWarning'] = c_sess['Warning']    
        if 'Error' in c_sess:
            session['AgentError'] = c_sess['Error']

        if 'DisconnectionCode' in c_sess:
            session['AgentDisconnectionCode'] = c_sess['DisconnectionCode']   

        if 'ClientInfo' in c_sess:
            session['ClientInfo'] = c_sess['ClientInfo']
        if 'ClientWarning' in c_sess:
            session['ClientWarning'] = c_sess['ClientWarning']
        if 'ClientError' in c_sess:
            session['ClientError'] = c_sess['ClientError']
        if 'ClientDisconnectionCode' in c_sess:
            session['ClientDisconnectionCode'] = c_sess['ClientDisconnectionCode']

        ChartsHeight = 180 + (session['Activities'].__len__() - point2self) * 30 + point2self * 70 + 20
        session['ChartsHeight'] = max(400, ChartsHeight)

        status = max([status for t, s, d, f, status, e in c_sess['Activities'] ])
        if 'OverallStatus' in c_sess.keys():
            if c_sess['OverallStatus'] > status:
                status = c_sess['OverallStatus']
        session['OverallStatus'] = status
        if status == 0:
            if 'PreloadSession' in session.keys() and session['PreloadSession']==True:
                sessions['preload'].append(session)
            else:    
                sessions['ok'].append(session)
        elif status == 1:
            sessions['warnings'].append(session)
        elif status == 2:
            sessions['errors'].append(session)

    for c_sess in clientSessions:
        point2self = 0
        session = {}
        session['HasAgentLog'] = False
        session['HasBrokerLog'] = False
        session['HasClientLog'] = True
        session['StartTime'] = Convert2TimeStr(c_sess['StartTime'])
        session['EndTime'] = Convert2TimeStr(c_sess['EndTime'])
        session['Duration'] = datetime.timedelta(0, int((c_sess['EndTime'] - c_sess['StartTime']) / 1000), 0).__str__()
        session['Bundles'] = []
        bundlename = c_sess['Bundle']
        session['Bundles'].append(bundlename)
        session['Activities'] = []
        for activity in c_sess['Activities']:
            logs = []
            for log in activity[5]:
                afile = log[1]
                idx = afile.find(bundlename)
                if idx:
                    afile = afile[idx:]
                htmlfile = afile.replace('\\', '_').replace('/', '_') + '.html'
                logs.append((log[0], afile, log[2], Convert2TimeStr(log[3]), log[4], htmlfile))
            session['Activities'].append((activity[0], activity[1], activity[2], activity[3], activity[4], logs))
            if activity[1] == activity[2]:
                point2self += 1

        if 'Info' in c_sess:
            session['ClientInfo'] = c_sess['Info']
        if 'Warning' in c_sess:
            session['ClientWarning'] = c_sess['Warning']
        if 'Error' in c_sess:
            session['ClientError'] = c_sess['Error']

        if 'DisconnectionCode' in c_sess:
            session['ClientDisconnectionCode'] = c_sess['DisconnectionCode']

        ChartsHeight = 180 + (session['Activities'].__len__() - point2self) * 30 + point2self * 70 + 20
        session['ChartsHeight'] = max(400, ChartsHeight)

        status = max([status for t, s, d, f, status, e in c_sess['Activities'] ])
        if 'OverallStatus' in c_sess.keys():
            if c_sess['OverallStatus'] > status:
                status = c_sess['OverallStatus']
        session['OverallStatus'] = status
        if status == 0:
            sessions['ok'].append(session)
        elif status == 1:
            sessions['warnings'].append(session)
        elif status == 2:
            sessions['errors'].append(session)

    sessions['ok'].sort(key=lambda x:x['StartTime'])
    idx = 0
    for session in sessions['ok']:
        idx += 1
        data = {'session': session, 'index': idx}
        vcdtlib.utils.PrintOutputToHtml("session_ok_" + str(idx) + ".html", 'tl_viewpcoip_session.html', data)
    sessions['preload'].sort(key=lambda x:x['StartTime'])
    idx = 0
    for session in sessions['preload']:
        idx += 1
        data = {'session': session, 'index': idx}
        vcdtlib.utils.PrintOutputToHtml("session_preload_" + str(idx) + ".html", 'tl_viewpcoip_session.html', data)    
    sessions['warnings'].sort(key=lambda x:x['StartTime'])
    idx = 0
    for session in sessions['warnings']:
        idx += 1
        data = {'session': session, 'index': idx}
        vcdtlib.utils.PrintOutputToHtml("session_warning_" + str(idx) + ".html", 'tl_viewpcoip_session.html', data)
    sessions['errors'].sort(key=lambda x:x['StartTime'])
    idx = 0
    for session in sessions['errors']:
        idx += 1
        data = {'session': session, 'index': idx}
        vcdtlib.utils.PrintOutputToHtml("session_error_" + str(idx) + ".html", 'tl_viewpcoip_session.html', data)

    return sessions

def ProcessErrorHighlighting(bundle, files):
    print('%s View Logs Errors Highlight Parser: processing %s' % (datetime.datetime.now().__str__(), bundle.name), file=sys.stderr)
    if bundle.GetBundleType() == 'Agent':
        parser_highlight.HighlightAgentBundleFiles(bundle, files)
    elif bundle.GetBundleType().startswith('Broker'):
        parser_highlight.HighlightBrokerBundleFiles(bundle, files)
    elif bundle.GetBundleType() == 'Client':
        parser_highlight.HighlightClientBundleFiles(bundle, files)

if __name__ == '__main__':
    vcdtlib.utils.FixStdout()
    Script().Execute()
else:
    Script().Register()

