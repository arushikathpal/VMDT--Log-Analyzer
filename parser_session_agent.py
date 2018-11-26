from __future__ import nested_scopes, generators, division, absolute_import, with_statement, print_function, unicode_literals
'''
Created on 12/29/2014
@author: Xiaolong Shi
'''

import sys, os, stat
import time
import string
import re
import datetime
import codecs
import traceback

import vcdtlib
from psutil import pid_exists

PROJ_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
if not PROJ_ROOT in sys.path:
    sys.path.append(PROJ_ROOT)

MODULE_ROOT = os.path.join(PROJ_ROOT, 'vcdt', 'scripts', 'viewpcoip')
if not MODULE_ROOT in sys.path:
    sys.path.append(MODULE_ROOT)

from helper import *
__AGT_SESSION_DEBUG__ = False
def AGT_SESSION_DEBUG_LOG(debugstr):
    global __AGT_SESSION_DEBUG__
    if __AGT_SESSION_DEBUG__:
        print(debugstr)

'''
 Session
 {
     'BrokerSessionID':  //Client&Broker
     'AgentSessionID':   //Broker&Agent
     'ClientTicketID':   //Client&Agent
     'StartTime':
     'EndTime':
     'Activities':[(TimeStamp,StartPointer,EndPointer,Call_Function,Status,Log context)]
 }
'''
def gettimestamp(line, timeMpattern, timeCpattern):
   m = re.match(timeMpattern, line)
   timestamp = -1
   if m:
      tic = datetime.datetime.strptime(m.group(1).encode('ascii'), timeCpattern.encode('ascii'))
      timestamp = int((tic - datetime.datetime(1970, 1, 1)).total_seconds() * 1000)
   return timestamp

def GetVersion(bundle):
    timestamp = 0
    version = 'Unknown'
    files = vcdtlib.fileutils.GetAllFiles(bundle, 'debuglog')
    for aFile in files:
        verinfo = get_version(aFile)
        if verinfo[0] > timestamp:
            version = verinfo[1]
            timestamp = timestamp
    return version

def get_version(aFile):
    # 2015-01-02T10:46:15.744+08:00 INFO  (0CEC-0D10) <3344> [wsnm_jms] Log for VMware View Agent, version=5.1.1 build-799444
    p = pattern(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*wssm.*version=(\d+\.\d+\.\d+ build\-\d+).*')
    with open_file(aFile) as f:
        for line in f:
            m = re.match(p, line)
            if m:
                return (Convert2Time(m.group(1), '%Y-%m-%dT%H:%M:%S'), m.group(2))
    return (0, 'Unknown')

def init_session():
   session = {
              'BrokerSessionID':'',
               'AgentSessionID':'',
               'ClientTicketID':'',
               'StartTime'     :-1,
               'EndTime'       :-1,
               'Activities'    :[],
               'pid'           :-1}
   return session
def printactivity(activity):
   print(activity)

def printsession(session):
   print("=================Session Started==================")
   print("BrokerSessionID = " + session['BrokerSessionID'])
   print("AgentSessionID = " + session['AgentSessionID'])
   print("ClientTicketID = " + session['ClientTicketID'])
   print("pid = " + str(session['pid']))
   if 'LogFlag' in session.keys():
       print('Log Flag = ' + str(session['LogFlag']))
   if 'protocol' in session.keys():
       print("protocol = " + session['protocol'])
   for a in session['Activities']:
      printactivity (a)
   if 'DisconnectionCode' in session.keys():
      print('Disconnect Code = ' + session['DisconnectionCode'])
   print("=================Session Ended====================")

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
   # print(activities)
   dlist = []
   for a in activities.keys():
      if activities[a][0] >= 2:
         dlist.extend(activities[a][2:])
         a1 = activities[a][1]
         for item in activities[a][2:]:
            # a2 = activities[a][item]
            session['Activities'][a1][5] += session['Activities'][item][5]
            session['Activities'][a1][4] = session['Activities'][item][4] if session['Activities'][item][4] > session['Activities'][a1][4] else session['Activities'][a1][4]
   dlist.sort(reverse=True)
   for i in dlist:
      del session['Activities'][i]
   return session

def mergesession(s1, s2):
   if s2['AgentSessionID'] != '' and s1['AgentSessionID'] == '':
      s1['AgentSessionID'] = s2['AgentSessionID']
   if s2['ClientTicketID'] != '' and s1['ClientTicketID'] == '':
      s1['ClientTicketID'] = s2['ClientTicketID']

   if 'preloadpid' in s2.keys():    
       if s1['pid'] == s2['preloadpid'] and s1['PreloadSession']!=True:
           s1['PreloadSession'] = True
           #s1['Warning']=[(('Warning', 'PCoIP preload session'))]
           s1.pop('Warning',None)
           s1['Info'].append(('SessionType', 'PCoIP preload session'))
           s1['OverallStatus']=0
           
               
   if s2['StartTime'] != -1 and s2['StartTime'] < s1['StartTime']:
      s1['StartTime'] = s2['StartTime'] 
   if s2['EndTime'] != -1 and s2['EndTime'] > s1['EndTime']:
      s1['EndTime'] = s2['EndTime']
      
   keys = ['Info', 'Warning', 'Error']
   for key in keys:
      if key in s2.keys():
         if key in s1.keys():
            s1[key] += s2[key]
         else:
            s1[key] = s2[key]

   s1['Activities'] = s1['Activities'] + s2['Activities']  # pcoip agent log is earlier than pcoip server log if the log time are the same
   s1['LogFlag'] |= s2['LogFlag']
   if 'DisconnectionCode' not in s1.keys() and 'DisconnectionCode' in s2.keys():
       s1['DisconnectionCode'] = s2['DisconnectionCode']
   s1['Activities'].sort()
   # s1['Bundle'] = s1['Bundle'] + "; " + s2['Bundle']
   # sorted(s1['Activities'], key = itemgetter(0,5))
   s1 = mergeactivities(s1)

   return s1

def checkstatus(session):
    status = 0
    for a in session['Activities']:
        status = a[4] if a[4] > status else status

    if 'OverallStatus' in session.keys():
        if session['OverallStatus'] > status:
            status = session['OverallStatus']

    return status

def addsession2list(session, sessions):
   session['OverallStatus'] = checkstatus(session)

   for s in sessions:
      if (session['LogFlag'] & s['LogFlag']):
          continue
      if (session['ClientTicketID'] != '' and session['ClientTicketID'] == s['ClientTicketID']) or \
      (session['BrokerSessionID'] != '' and session['BrokerSessionID'] == s['BrokerSessionID']) or \
      (session['AgentSessionID'] != '' and session['AgentSessionID'] == s['AgentSessionID']) or \
      (session['pid'] != -1 and session['pid'] == s['pid']):
         s = mergesession(s, session)
         return sessions

   session = mergeactivities(session)  # merge the activities that have same func name
   sessions.append(session)
   # check if there are some error existing
   # if error existing, add the session to session list
   return sessions

def processdbglog(bundle, file, sessions):
   timeMpattern = pattern(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}).+')
   timeCpattern = "%Y-%m-%dT%H:%M:%S.%f"
   #[wsnm_desktop] <PCoIPPreload> [wsnm_desktop] Start PCoIP preload.
   pcoippreloadpattern= pattern(r'.*Start PCoIP preload')
   # [wsnm_desktop] DesktopManager got a StartSession message {SESSION:54ab_***_e762}
   agentstartsessionpattern = pattern(r'.*DesktopManager got a StartSession message.*\{SESSION:(.*)\}.*')
   # [wsnm_desktop] Starting protocol PCOIP... {SESSION:54ab_***_e762}
   agentstartlaunchpcoippattern = pattern(r'.*\(.*-(.*)\).*Starting protocol (.*)\.\.\..*\{SESSION:(.*)\}.*')
   # [wsnm_desktop] PCoIP connection request succeeded! (handle=0x1b) {SESSION:54ab_***_e762}
   agentstartpcoipOKpattern = pattern(r'.*\[wsnm_desktop\] PCoIP connection request succeeded.*')
   # [wsnm_desktop] Protocol PCOIP is listening on 10.117.175.55:4172 {SESSION:54ab_***_e762}
   # [pcoip_server_win32] Program 'pcoip_server_win32 - PCoIP Server' started, version=3,12,3,26912:soft_pcoip_rc_3_12_3, pid=0x388, buildtype=release, usethread=0, closeafterwrite=0
   # agentonstartsessioncompletedpattern = pattern(r'.*\[pcoip_server_win32\] Program \'pcoip_server_win32 - PCoIP Server\' started.*')
   agentonstartsessioncompletedpattern = pattern(r'.*\[wsnm_desktop\] Protocol PCOIP is listening on.*')
   # 2014-09-29T09:05:38.588+08:00 DEBUG (11F8-0860) <2144> [pcoip_mfw] pcoip disconnected
   agentpcoipdisconnectedpattern = pattern(r'.*pcoip disconnected.*')
   # [wsnm_desktop] PCoIP connection complete:
   agentpcoipconnectcompletepattern = pattern(r'.*PCoIP connection complete.*')
   # (16BC-0500) <1280> [pcoip_mfw] Program 'pcoip_server_win32 - PCoIP Server' started, version=3,12,3,26912:soft_pcoip_rc_3_12_3, pid=0x16BC, buildtype=release, usethread=0, closeafterwrite=0
   agentpcoippidpattern = pattern(r'.*\[pcoip_server_win32\].*\'pcoip_server_win32 - PCoIP Server\' started,.*pid=0x(.*), buildtype.*')
   # [wsnm_desktop] session::disconnect session disconnect done: 1
   agentpcoipdisconnectdonepattern = pattern(r'.*session::disconnect session disconnect done.*')
   # [wsnm_desktop] startSession refused on MaxSession limit, user VIEWCONNECTION\vmware-china {SESSION:982a_***_c7d9}
   agentstartsessionfailedpattern = pattern(r'.*\[wsnm_desktop\] startSession refused on MaxSession limit, user.*')

   # 2014-12-19T14:13:10.047-06:00 ERROR (0364-04F0) <1264> [wsnm_desktop] vmwProtocolCnx::sessionSwitch: session switch failure
   # 2014-09-03T09:46:32.707-05:00 ERROR (016C-2860) <10336> [wsnm_desktop] PCoIPCnx::SessionSwitch: session switch failure
   sessionswitchfailedpattern = pattern(r'.*\:\:[Ss]essionSwitch: session switch failure.*')
   preloadpcoip=0
   lineno = 0
   with open_file(file) as f:
      stag = 0
      session = init_session()
      session['Bundle'] = bundle.name
      session['HasAgentLog'] = True
      session['HasBrokerLog'] = False
      session['HasClientLog'] = False
      session['LogFlag'] = 4
      
      for line in f.readlines():
         lineno += 1
         timestamp = gettimestamp(line, timeMpattern, timeCpattern)
         m = re.match(agentstartsessionpattern, line)
         if m:
            if stag == 1:
               session['EndTime'] = timestamp
               sessions = addsession2list(session, sessions)
               stag = 0
               continue
            if stag == 0:
                session = init_session()
                session['Bundle'] = bundle.name
                session['HasAgentLog'] = True
                session['HasBrokerLog'] = False
                session['HasClientLog'] = False
                session['LogFlag'] = 4
            # session['AgentSessionID'] = m.group(1)
                stag = 1
                session['StartTime'] = timestamp
                session['Activities'].append([timestamp, ActivityRoles.broker, ActivityRoles.agent, Activities.StartSession, 0, logcontext(0, file, lineno, timestamp, '')])
         m = re.match(agentstartlaunchpcoippattern, line)
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent, ActivityRoles.agent_pcoip_agent, Activities.LaunchPCoIPServer, 0, logcontext(0, file, lineno, timestamp, '')])
            # session['AgentSessionID'] = m.group(3)
            session['protocol'] = m.group(2)

         m = re.match(agentstartpcoipOKpattern, line)
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent_pcoip_agent, ActivityRoles.agent, Activities.PCoIPServerIsOK, 0, logcontext(0, file, lineno, timestamp, '')])
         m = re.match(agentonstartsessioncompletedpattern, line)
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent, ActivityRoles.broker, Activities.CompleteStartSession, 0, logcontext(0, file, lineno, timestamp, '')])
         m = re.match(agentpcoipconnectcompletepattern, line)
         if m:
            if stag == 1:
                session['Activities'].append([timestamp, ActivityRoles.agent, ActivityRoles.broker, 'connection completed', 0, logcontext(0, file, lineno, timestamp, '')])
                stag = 0
                session['EndTime'] = timestamp
                sessions = addsession2list(session, sessions)
                
         m=re.match(pcoippreloadpattern, line)
         if m:
             preloadpcoip=1
         
         m = re.match(agentpcoippidpattern, line)
         if m:
            pid = m.group(1)
            session['pid'] = int(pid, 16)
            if preloadpcoip==1:
                session['preloadpid']=session['pid']
                print("Hey i got executed",file=sys.stderr)
                addsession2list(session, sessions)
                preloadpcoip=0 
            
         m = match(agentstartsessionfailedpattern, line)
         if m:
            # pass
            if stag == 1:
                session['Activities'].append([timestamp, ActivityRoles.agent, ActivityRoles.broker, Activities.CompleteStartSession, 2, logcontext(2, file, lineno, timestamp, 'startSession refused on MaxSession limit')])
                session['EndTime'] = timestamp
                sessions = addsession2list(session, sessions)
                stag = 0
         m = match(sessionswitchfailedpattern, line)
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent, ActivityRoles.agent, Activities.SessionSwitchFailed, 2, logcontext(2, file, lineno, timestamp, 'Please apply Microsoft hotfixes 2578159&2661332, refer to KB 2073945 for details.')])

   return sessions

def DetectTimeFormate(line):
   if line[10] == 'T':
      timeMpattern = pattern(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}).+')
      timeCpattern = "%Y-%m-%dT%H:%M:%S.%f"
   if line[10] == ',':
      timeMpattern = pattern(r'(\d{2}/\d{2}/\d{4}, \d{2}:\d{2}:\d{2}\.\d{3}).+')
      timeCpattern = "%m/%d/%Y, %H:%M:%S.%f"
   return(timeMpattern, timeCpattern)

def processpcoipagentlog(bundle, file, sessions):
   agentbegins = 0
   
   pcoipagentbegins = pattern(r'.*pcoip_agent begins.')
   
   preloadpid = pattern(r'.*Using direct CreateProcess:(.*) pid:(.*).*')

   pid = pattern(r'.*pid: 0x(.*),.*')  
      
   timeMpattern = pattern(r'(\d{2}/\d{2}/\d{4}, \d{2}:\d{2}:\d{2}\.\d{3}).+')

   timeCpattern = "%m/%d/%Y, %H:%M:%S.%f"

   # 10/17/2014, 15:56:12.887> LVL:2 RC:   0           AGENT :pcoip_agent_connect_req
   #04/06/2015, 04:01:34.183> LVL:2 RC:   0           AGENT :pcoip_agent_connect_req: ==========>  New connection request <===========
   pcoipagenstartpattern = pattern(r'.*AGENT :pcoip_agent_connect_req$|.*AGENT :pcoip_agent_connect_req: ==========>  New connection request <===========.*')
   # PRI :pcoip_agent_connect_req: Session ID for Soft Host: Tag:'GtieIDUb0q4A' Value:1ad89e20351bd2ae
   # 04/06/2015, 04:01:34.207> LVL:2 RC:   0             PRI :pcoip_agent_connect_req: {s_tag:0xa18cbc0569abdc38} Session ID for Soft Host: Tag:'oYy8BWmr3DgA' Value:a18cbc0569abdc38
   pcoipagentsessionIDpattern = pattern(r'.*Tag:\'(.*)\' Value:(.*).*')
   # AGENT :Launching pcoip_server_win32
   # AGENT :tera_agent_launch_server: {s_tag:0xa18cbc0569abdc38} Launching pcoip_server_win32
   pcoipagentluanchpcoippattern = pattern(r'.*AGENT :.*Launching pcoip_server_win32.*')
   # AGENT :Got ready message.
   # AGENT :pcoip_agent_connect_req: {s_tag:0xa18cbc0569abdc38} [1] Got ready message.
   pcoipagentgotreadymessagpattern = pattern(r'.*AGENT :Got ready message.*')
   # 10/17/2014, 15:39:06.067> LVL:2 RC:   0           AGENT :Sending connection response ok.
   pcoipagentsendokpattern = pattern(r'.*AGENT :Sending connection response ok.*')
   # 05/28/2015, 12:07:18.663> LVL:1 RC:   0           AGENT :pcoip_agent_connect_req: {s_tag:0x5957242b5909e423} [13] No reply came back from the server in time.

   # 10/20/2014, 20:05:45.537> LVL:2 RC:   0           AGENT :monitor thread: exiting
   pcoipagentendpattern = pattern(r'.*connection_response.*')
   # 10/20/2014, 20:05:45.084> LVL:2 RC:   0           AGENT :MBX_CON_CLOSED
   pcoipagentclosemailboxpattern = pattern(r'.*AGENT :MBX_CON_CLOSED.*')
   # Server has quitted in wait loop.
   serverquitinwaitloop = pattern(r'.*Server has quitted in wait loop.*')
   # Server has timed out or server has quitted in wait loop
   serverlaunchfailed = pattern(r'.*Server has timed out or server has quitted in wait loop.*')
   # mb_send_acknowledgement failed to write to mailbox %08x

   # Could not open mailbox connection to server.
   isTimeFormateDetected = False
   lineno = 0
   with open_file(file) as f:
      session = init_session()
      session['Bundle'] = bundle.name
      session['HasAgentLog'] = True
      session['HasBrokerLog'] = False
      session['HasClientLog'] = False
      session['LogFlag'] = 2
      stag = 0
      for line in f.readlines():
         lineno += 1
         if isTimeFormateDetected == False:
            (timeMpattern, timeCpattern) = DetectTimeFormate(line)
            isTimeFormateDetected = True

         timestamp = gettimestamp(line, timeMpattern, timeCpattern)

              
             
         m = re.match(pcoipagenstartpattern, line.strip())
         if m:
            if stag == 1:
               session['EndTime'] = timestamp
               sessions = addsession2list(session, sessions)
               stag = 0
               continue
            if stag == 0:
                session = init_session()
                session['Bundle'] = bundle.name
                session['HasAgentLog'] = True
                session['HasBrokerLog'] = False
                session['HasClientLog'] = False
                session['LogFlag'] = 2
                stag = 1
                session['StartTime'] = timestamp

         m = re.match(pcoipagentbegins, line)
         if m:
             print("Matched pcoip agent begins", file=sys.stderr)
             agentbegins = 1
        
         m = re.match(preloadpid, line)
         if m and agentbegins == 1:
             
             agentbegins = 0
             m = re.match(pid, line.strip())
             pid = int(m.group(1), 16)
             session['preloadpid'] = pid
             
             print("HeyIgot executed")
             sessions = addsession2list(session, sessions)
         
            # check whether the pcoip server log is there
         m = re.match(pcoipagentendpattern, line.strip())
         if m:
            stag = 0
            session['EndTime'] = timestamp
            print("Printing current session", session, file=sys.stderr)
            sessions = addsession2list(session, sessions)
            session = init_session()
            session['Bundle'] = bundle.name
            session['HasAgentLog'] = True
            session['HasBrokerLog'] = False
            session['HasClientLog'] = False
            session['LogFlag'] = 2
         m = re.match(pcoipagentsessionIDpattern, line.strip())
         if m:
            tag = m.group(1)
            session['ClientTicketID'] = tag  # + "_" + tval
         m = re.match(pcoipagentluanchpcoippattern, line.strip())
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent_pcoip_agent, ActivityRoles.agent_pcoip_server, Activities.LaunchPCoIPServer , 0, logcontext(0, file, lineno, timestamp, '')])
            session['Activities'].append([timestamp, ActivityRoles.agent_pcoip_agent, ActivityRoles.agent_pcoip_server, Activities.LaunchingPCoIPServer, 0, logcontext(0, file, lineno, timestamp, '')])
         m = re.match(pcoipagentgotreadymessagpattern, line.strip())
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_agent, Activities.PCoIPServerReady, 0, logcontext(0, file, lineno, timestamp, '')])
         m = re.match(pcoipagentsendokpattern, line.strip())
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent_pcoip_agent, ActivityRoles.agent, Activities.PCoIPServerIsOK, 0, logcontext(0, file, lineno, timestamp, '')])
         m = re.match(pcoipagentclosemailboxpattern, line.strip())
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_agent, 'mailbox close', 0, logcontext(0, file, lineno, timestamp, '')])
         m = match(serverquitinwaitloop, line)
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_agent, Activities.PCoIPServerReady, 2, logcontext(1, file, lineno, timestamp, 'Server has quitted in wait loop')])
         m = match(serverlaunchfailed, line)
         if m:
            session['Activities'].append([timestamp, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_agent, Activities.PCoIPServerReady, 2, logcontext(1, file, lineno, timestamp, 'Server has timed out')])

   return sessions

def pattern(str):
   return re.compile(str)

def match(pattern, str):
   return re.match(pattern, str)
def logcontext(status, file, lineno, timestamp, comment):
    return [[status, getfilename(file), lineno, timestamp, comment]]

def processpcoipserverlog(bundle, file):
   timeMpattern = pattern(r'(\d{2}/\d{2}/\d{4}, \d{2}:\d{2}:\d{2}\.\d{3}).+')

   timeCpattern = "%m/%d/%Y, %H:%M:%S.%f"
   # PRI :tera_pri_server_reserve: Reservation Session ID: 'ICbfLbUx6HQA' Value:2026df2db531e874
   sessionidpattern = pattern(r'.*Reservation Session ID.*: (.*)')
   # 09/29/2014, 09:04:53.903> LVL:2 RC:   0          COMMON :-- pcoip_server begins.
   pcoipserverstartpattern = pattern(r'.*COMMON :-- pcoip_server begins.*')
   # MGMT_SYS :Boot-up complete
   pcoipserverreadypattern = pattern(r'.*SERVER :server main: sending ready message.*')
   # 09/29/2014, 09:04:58.864> LVL:3 RC:   0       MGMT_SSIG :(mgmt_ssig_handle_rx_xml): Received valid PCOIP_HELLO from peer
   sessionnegotiationpattern = pattern(r'.*Received valid PCOIP_HELLO from peer.*')
   # SCNET :(scnet_open_accepted_socket): Server accepting connection from 10.117.173.181:10525.
   pcoipserveracceptconnectionpattern = pattern(r'.*SCNET :\(scnet_open_accepted_socket\): Server accepting connection from.*')
   # SCNET :(ssl_server_name_cback): Received SSL Client Hello: server name = 10.117.172.68
   sessioninitiating = pattern(r'.*Received SSL Client Hello: server name =.*')
   # MGMT_SCHAN :SCDAT: master_ready(): SCDAT_MSG_OPEN_COMPLETE
   pcoipserveracceptedconnectionpattern = pattern(r'.*master_ready\(\): SCDAT_MSG_OPEN_COMPLETE.*')
   # MGMT_SSIG :Session established successfully (10.117.173.181, 34-17-EB-96-9A-71, PRI: 0)
   pcoipsessionestablishedpattern = pattern(r'.*MGMT_SSIG :Session established successfully.*')
   # VGMAC :Connected the PCoIP socket to peer IP 10.117.173.181 peer [UDP] port 50002
   pcoipudpconnecttopattern = pattern(r'.*VGMAC :Connected the PCoIP socket to peer IP.*')
   # MGMT_SYS :CONNECTED (10.117.173.181, 34-17-EB-96-9A-71)
   pcoipudpconnectedpattern = pattern(r'.*MGMT_SYS :CONNECTED.*')
   # MGMT_SYS :SESSION ACTIVE
   sessionactivepattern = pattern(r'.*MGMT_SYS :SESSION ACTIVE.*')
   # MGMT_SSIG :Request to reset session (PRI: 0)
   sessionresetpattern = pattern(r'.*MGMT_SSIG :Request to reset session.*')
   # MGMT_SSIG :(mgmt_ssig_open_handle_rx_apdu_bye): Received BYE APDU from: 10.117.173.181, PRI: 0
   # MGMT_PCOIP_DATA :OPEN: Received BYE (disconnect cause=0x300).  Disconnecting the session ...
   sessionreceivebyeAPDUpattern = pattern(r'.*Received BYE APDU from: (.*),.*')
   # SERVER :server main: exiting
   pcoipserverquitpattern = pattern(r'.*SERVER :server main: exiting.*')
   # MGMT_PCOIP_DATA :OPEN: Received BYE (disconnect cause=0x300).  Disconnecting the session ...
   pcoipsessionbyereq = pattern(r'.*MGMT_PCOIP_DATA :OPEN: Received BYE \(disconnect cause=(.*)\).  Disconnecting the session.*')
   # MGMT_IMG :Topology: valid:1 (res supported:1, no overlap:1, num active displays:2)
   # 11/10/2014, 08:04:27.021> LVL:0 RC:-500    IMG_FRONTEND :configure_displays: Warning - displays overlap: [LRTB]: [  0,1279,  0,1023] X [1024,2303,  0,1023]
   # topologyoverlappattern = pattern(r'.*MGMT_IMG :Topology: valid:\d \(res supported:\d, no overlap:(\d), num active displays:\d\).*')
   topologyoverlappattern = pattern(r'.*IMG_FRONTEND :configure_displays: Warning - displays overlap:.*')
   # 10/20/2014, 20:03:16.478> LVL:1 RC:   0           VGMAC :Session stats: Average TX=0.087971 average RX=0.0271047 (Mbps) Loss=0.00%/0.00% (R/T)
   pcoipdatapattern = pattern(r'.*Loss=(\d*\.?\d*)%/(\d*\.?\d*).*')
   # 12/24/2014, 15:25:48.936> LVL:2 RC:   0       MGMT_SSIG :Session timeout!
   MGMT_SSIG_session_timeout = pattern(r'.* MGMT_SSIG :Session timeout!.*')
   # 12/24/2014, 15:25:48.936> LVL:1 RC:-500          COMMON :poll_sockets failed to generate 1 callbacks!
   poll_sockets_failedpattern = pattern(r'.*poll_sockets failed to generate 1 callbacks.*')

   # 10/21/2015, 18:35:04.950> LVL:1 RC:-504 MGMT_PCOIP_DATA :Unable to communicate with peer on PCoIP media channels (data manager ping timer expired)
   pingtimerexpired = pattern(r'.*Unable to communicate with peer on PCoIP media channels \(data manager ping timer expired\).*')

   minidumppattern = pattern(r'.*Critical Exception/Reset Detected!! Saving a minidump file.*')

   minidumpfilepattern = pattern(r'.*Minidump File saved as (.*)')

   pcoipdisconnectcodepattern = pattern(r'.*disconnect cause \(0x(.*)\)')

   pcoipversionpattern = pattern(r'.*MGMT_SYS :Software Build ID: (.*)')

   # 10/20/2014, 20:00:52.790> LVL:2 RC:   0           SCNET :(scnet_open_accepted_socket): Server accepting connection from 10.117.173.181:18222.
   pcoipclientIPpattern = pattern(r'.*SCNET :\(scnet_open_accepted_socket\): Server accepting connection from (.*):(.*)\.')

   # 10/20/2014, 20:00:52.790> LVL:2 RC:   0           SCNET :(scnet_open_accepted_socket): Server connecting on address 10.117.175.55:4172.
   pcoipserverIPpattern = pattern(r'.*SCNET :\(scnet_open_accepted_socket\): Server connecting on address (.*):(.*)\.')

   # 2017-02-24T11:18:09.527+09:00> LVL:1 RC:-504 MGMT_PCOIP_DATA :Invite packet not received, aborting session
   pcoipserverinvitenotrecd = pattern(r'.*MGMT_PCOIP_DATA :Invite packet not received, aborting session')
   
   #2017-03-28T20:26:35.196+05:30> LVL:2 RC:   0        MGMT_IMG :CODEC: State change from CODEC_RUNNING to CODEC_DISABLED
   codecrunningtodisabled= pattern(r'.*MGMT_IMG :CODEC: State change from CODEC_RUNNING to CODEC_DISABLED')
   #2017-03-28T20:26:35.196+05:30> LVL:2 RC:   0        MGMT_IMG :CODEC: State change from CODEC_DISABLED to CODEC_CFG_EXCHANGE
   codecdiabledtocfgexchange= pattern(r'.*MGMT_IMG :CODEC: State change from CODEC_DISABLED to CODEC_CFG_EXCHANGE')
   #2017-03-28T20:26:46.437+05:30> LVL:2 RC:   0        MGMT_IMG :CODEC: State change from CODEC_CFG_EXCHANGE to CODEC_DMT_EXCHANGE
   codeccfgtodmtexchange=pattern(r'MGMT_IMG :CODEC: State change from CODEC_CFG_EXCHANGE to CODEC_DMT_EXCHANGE')
   #2017-03-28T20:26:34.185+05:30> LVL:0 RC:   0             IPC :cSW_HOST_IPC: New sub-session ID is 1
   subsessionid=pattern(r'.*IPC :cSW_HOST_IPC: New sub-session ID is \d+') 
   #2017-03-28T20:26:46.480+05:30> LVL:2 RC:   0        MGMT_IMG :CODEC: State change from CODEC_DMT_EXCHANGE to CODEC_RUNNING
   codecdmtexchangetocodecrunning=pattern(r'.*MGMT_IMG :CODEC: State change from CODEC_DMT_EXCHANGE to CODEC_RUNNING')
   
   starttime = '';
   endtime = '';
   session = init_session()
   session['Bundle'] = bundle.name
   session['Info'] = []
   session['Info'].append(('Bundle Name', bundle.name))
   session['HasAgentLog'] = True
   session['HasBrokerLog'] = False
   session['HasClientLog'] = False
   session['LogFlag'] = 1
   session['Warning'] = []
   session['Error'] = []
   session['PreloadSession'] = False
   lineno = 0
   havePCoIPData = False
   isClientConnected = False
   isServerReady = False
   isExited = False
   isTimeFormateDetected = False

   with open_file(file) as f:
      for line in f.readlines():
         lineno += 1
         if isTimeFormateDetected == False:
            (timeMpattern, timeCpattern) = DetectTimeFormate(line)
            isTimeFormateDetected = True

         timestamp = gettimestamp(line, timeMpattern, timeCpattern)
         endtime = timestamp
         if not starttime:
            starttime = endtime
         if "Session ID" in line:
            id = re.match(sessionidpattern, line.strip()).group(1)
            if "\'" in id:
                id = id.split(' ')[0][1:-1]
            session['ClientTicketID'] = id  # (id + "_" + val).strip()

         m = re.match(pcoipserverstartpattern, line)
         if m:
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_agent, ActivityRoles.agent_pcoip_server, Activities.LaunchingPCoIPServer, 0, logcontext(0, file, lineno, endtime, '')])
         m = re.match(pcoipserverreadypattern, line)
         if m:
            isServerReady = True
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_agent, Activities.PCoIPServerReady, 0, logcontext(0, file, lineno, endtime, '')])
         m = re.match(pcoipserveracceptconnectionpattern, line)
         if m:
            isClientConnected = True
            session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, Activities.TcpConnectReq, 0, logcontext(0, file, lineno, endtime, '')])
         m = re.match(sessionnegotiationpattern, line)
         if m:
            isClientConnected = True
            session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, Activities.SessionNegotiation, 0, logcontext(0, file, lineno, endtime, '')])
         m = re.match(sessionactivepattern, line)
         if m:
            isClientConnected = True
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.client_pcoip_client, Activities.SessionActive, 0, logcontext(0, file, lineno, endtime, '')])
         m = re.match(sessionreceivebyeAPDUpattern, line)
         if m:
            session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, "TCP BYE", 0, logcontext(0, file, lineno, endtime, '')])
         m = re.match(pcoipserverquitpattern, line)
         if m:
            isExited = True
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_agent, Activities.PCoIPServerQuit, 0, logcontext(0, file, lineno, endtime, '')])

         m = match(sessioninitiating, line)
         if m:
            session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, Activities.SessionInitiating, 0, logcontext(0, file, lineno, endtime, '')])

         m = match(pcoipserveracceptedconnectionpattern, line)
         if m:
            isClientConnected = True
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.client_pcoip_client, Activities.TcpConnectRes, 0, logcontext(0, file, lineno, endtime, '')])

         m = match(pcoipsessionestablishedpattern, line)
         if m:
            session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, Activities.SessionEstablished, 0, logcontext(0, file, lineno, endtime, '')])

         m = match(pcoipudpconnecttopattern, line)
         if m:
            isClientConnected = True
            session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, Activities.UdpConnectReq, 0, logcontext(0, file, lineno, endtime, '')])

         m = match(pcoipudpconnectedpattern, line)
         if m:
            isClientConnected = True
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.client_pcoip_client, Activities.UdpConnectRes, 0, logcontext(0, file, lineno, endtime, '')])

         m = match(sessionresetpattern, line)
         if m:
            session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, Activities.SessionReset, 0, logcontext(0, file, lineno, endtime, '')])
         m = match(pcoipsessionbyereq, line)
         if m:
            # print(m.group(1))
            session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, Activities.ByeReq, 0, logcontext(0, file, lineno, endtime, '')])
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.client_pcoip_client, Activities.ByeRes, 0, logcontext(0, file, lineno, endtime, '')])

         if not isExited and isClientConnected:
            m = match(pcoipdatapattern, line)
            if m:
               if '0.00' != m.group(1) or '0.00' != m.group(2):
                  session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.client_pcoip_client, Activities.PCoIPData, 1, logcontext(1, file, lineno, endtime, 'Data loss! Please check the network.')])
               elif not havePCoIPData:
                  havePCoIPData = True
                  session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.client_pcoip_client, Activities.PCoIPData, 0, logcontext(0, file, lineno, endtime, '')])
            else:
               m = match(pingtimerexpired, line)
               if m:
                  session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.client_pcoip_client, Activities.PCoIPData, 2, logcontext(2, file, lineno, endtime, 'Unable to communicate with client! Please check if network was broke or view client has no response')])
                  isExited = True
               m = match(pcoipserverinvitenotrecd, line)
               if m:   
                  session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.client_pcoip_client, 'UDP Connection Failed', 2, logcontext(2, file, lineno, endtime, 'Invite packet not received, aborting session')])
                  isExited = True   
         '''
         m = match(MGMT_SSIG_session_timeout, line)
         if m:
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_server, Activities.SessionTimeout, 1, logcontext(1, file, lineno, endtime, 'please upgrade VM to the latest MS patch')])
         m = match(poll_sockets_failedpattern, line)
         if m:
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_server, Activities.SocketGenerateCallbackError, 1, logcontext(1, file, lineno, endtime, 'please upgrade VM to the latest MS patch')])
         '''
         m = match(topologyoverlappattern, line)
         if m:
            # overlap = m.group(1)
            # if overlap == '0':
            #    overlap = 2
            #    com = 'Topology Overlap Error'
            # else:
            #    overlap = 0
            #    com = 'No Topology Overlap'
            # session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, Activities.TopologyOverlap, overlap, logcontext(overlap, file, lineno, endtime, com)])
            session['Activities'].append([endtime, ActivityRoles.client_pcoip_client, ActivityRoles.agent_pcoip_server, Activities.TopologyOverlap, 2, logcontext(2, file, lineno, endtime, 'Topology Overlap Error')])
         m = match(minidumppattern, line)
         if m:
            session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_server, 'Crashed', 2, logcontext(2, file, lineno, endtime, 'PCoIP Server Crashed')])
         m = match(minidumpfilepattern, line)
         if m:
            tmp = m.group(1)
            # session['Activities'].append([endtime, ActivityRoles.agent_pcoip_server, ActivityRoles.agent_pcoip_server, 'Saving a dumpfile', 2, logcontext(2, file, lineno, endtime, 'Dumpfile Generated')])
            session['Error'].append(('Fatal Error', 'PCoIP server caught a fatal exception and core dumped, which caused the connection break. Please analyze %s for the root cause.' % (tmp[tmp.rfind('\\') + 1:])))
         m = match(pcoipdisconnectcodepattern, line)
         if m:
            session['DisconnectionCode'] = GetDisconnectCodeString(int(m.group(1), 16))
         m = match(pcoipversionpattern, line)
         if m:
            session['Info'].append(('PCoIP Version', m.group(1)))
         m = match(pcoipclientIPpattern, line)
         if m:
            session['Info'].append(('Client IP', m.group(1)))
         m = match(pcoipserverIPpattern, line)
         if m:
            session['Info'].append(('Server IP', m.group(1)))

   session['StartTime'] = starttime
   session['EndTime'] = endtime
   session['pid'] = int(file.split(os.path.sep)[-1].split(r'.')[0].split('_')[-1], 16)
   if 'OverallStatus' not in session.keys():
       session['OverallStatus'] = 0
   for a in session['Activities']:
       session['OverallStatus'] = a[4] if a[4] > session['OverallStatus'] else session['OverallStatus']

   if not isServerReady  and 2 > session['OverallStatus']:
       session['OverallStatus'] = 2
       session['Error'].append(('Error', 'PCoIP server is not ready for connecting'))

   if not isClientConnected and 0 == session['OverallStatus']:
       session['OverallStatus'] = 1
       session['Warning'].append(('Warning', 'PCoIP server is ready, but no client connected to it'))
       
   return session

def getfilename(file):
   # return file.split('\\')[-1]
   return file

def filtersessions(sessions):
    # print("===========before filter==============")
    # print(len(sessions))
    # return sessions
    dellist = []

    for s in sessions:
        if s['OverallStatus'] == 0:
            # print(s['LogFlag'])
            if s['LogFlag'] != 7 and not (s['LogFlag'] & 1) :
                dellist.append(s)
    for it in dellist:
        sessions.remove(it)
    # print("===========after filter==============")
    # print(len(sessions))
    return sessions
def parser_agent_sessions(bundle):
   sessions = []
   dbgfiles = vcdtlib.fileutils.GetAllFiles(bundle, 'debuglog')
   pcoipagentfiles = vcdtlib.fileutils.GetAllFiles(bundle, 'pcoipagent')
   pcoipserverfiles = vcdtlib.fileutils.GetAllFiles(bundle, 'pcoipserver')
   for file in pcoipserverfiles:
      try:
         print('   Info: Processing %s' % (bundle._GetFormatBundleFileName(file)), file=sys.stderr)
         session = processpcoipserverlog(bundle, file)
         sessions = addsession2list(session, sessions)
      except Exception as e:
         print('   Error: %s' % (e), file=sys.stderr)
         print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)
   print("The sessions captured by processpcoipserverlogs is", sessions , file=sys.stderr)   
   
   for file in pcoipagentfiles:
      try:
         print('   Info: Processing %s' % (bundle._GetFormatBundleFileName(file)), file=sys.stderr)
         sessions = processpcoipagentlog(bundle, file, sessions)
      except Exception as e:
         print('   Error: %s' % (e), file=sys.stderr)
         print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)
   print("The sessions captured by processpcoipagentlogs is", sessions , file=sys.stderr)   
      
   for file in dbgfiles:
      try:
         print('   Info: Processing %s' % (bundle._GetFormatBundleFileName(file)), file=sys.stderr)
         sessions = processdbglog(bundle, file, sessions)
         
      except Exception as e:
         print('   Error: %s' % (e), file=sys.stderr)
         print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)
   print("The sessions captured by processdbglogs is", sessions , file=sys.stderr)   
      
   try:
      sessions = filtersessions(sessions)
   except Exception as e:
      print('   Error: %s' % (e), file=sys.stderr)
      print('   Callstack: %s' % (traceback.format_exc()), file=sys.stderr)
   # for s in sessions:
   # printsession(s)

   return sessions

if __name__ == '__main__':
    pass
