"""Offline ARP MITM teaching simulation.

This model uses synthetic events only. It opens no sockets and sends no packets.
Run: python run_lab.py
"""
from __future__ import annotations
import csv, json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import textwrap
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'results'
OUT.mkdir(exist_ok=True)
HOSTS = [f'192.168.40.{n}' for n in range(51, 59)]
GATEWAY_IP = '192.168.40.1'
GATEWAY_MAC = '00:1A:2B:3C:4D:5E'
ATTACKER_MAC = 'AA:BB:CC:DD:EE:FF'
FLOWS_PER_HOST = 3

CONDITIONS = [
 {'name':'Baseline / no attacker','dai':False,'tls':False,'attacker':False},
 {'name':'ARP MITM / HTTP','dai':False,'tls':False,'attacker':True},
 {'name':'ARP MITM / TLS validated','dai':False,'tls':True,'attacker':True},
 {'name':'DAI + snooping / HTTP','dai':True,'tls':False,'attacker':True},
 {'name':'Layered: DAI + TLS + HSTS','dai':True,'tls':True,'attacker':True},
]

def simulate():
    rows=[]; events=[]
    start=datetime(2026,10,28,10,0,0,tzinfo=timezone.utc)
    for ci,c in enumerate(CONDITIONS):
        claims=2*len(HOSTS) if c['attacker'] else 0
        dropped=claims if c['dai'] else 0
        accepted=claims-dropped
        redirected=len(HOSTS) if accepted else 0
        flows_generated=len(HOSTS)*FLOWS_PER_HOST
        intercepted_flows=redirected*FLOWS_PER_HOST
        exposed=intercepted_flows if (intercepted_flows and not c['tls']) else 0
        credentials=redirected if exposed else 0
        tamper=exposed > 0
        metadata=intercepted_flows if (intercepted_flows and c['tls']) else 0
        rows.append({
          'condition':c['name'],'hosts_in_scope':len(HOSTS),
          'forged_arp_claims_sent':claims,'forged_claims_dropped_by_dai':dropped,
          'forged_claims_accepted':accepted,'hosts_redirected':redirected,
          'sensitive_flows_generated':flows_generated,'cleartext_flows_visible_to_attacker':exposed,
          'synthetic_credentials_exposed':credentials,
          'application_payload_tampering_possible':str(tamper).lower(),
          'encrypted_flow_metadata_observable':metadata,
          'availability_disruption_still_possible':str(bool(redirected)).lower()
        })
        ts=start+timedelta(minutes=ci*10)
        if not c['attacker']:
            events.append([ts.isoformat(),'BASELINE','-', '-', 'No attacker; no forged claim generated',c['name']])
            continue
        for h in HOSTS:
            for direction in ('victim-to-gateway','gateway-to-victim'):
                ev='DAI_DROP' if c['dai'] else 'FORGED_ARP_ACCEPTED'
                note='Synthetic forged mapping rejected against trusted binding' if c['dai'] else 'Synthetic victim cache changed to attacker MAC'
                events.append([(ts+timedelta(seconds=len(events)%43)).isoformat(),ev,h,GATEWAY_IP,note,c['name']])
            if not c['dai']:
                for fi in range(FLOWS_PER_HOST):
                    kind='TLS_RECORD_OBSERVED' if c['tls'] else 'HTTP_SECRET_EXPOSED'
                    note='Payload encrypted; metadata only in model' if c['tls'] else 'Synthetic clear-text login/payment field visible'
                    events.append([(ts+timedelta(seconds=60+fi*2)).isoformat(),kind,h,f'flow-{fi+1}',note,c['name']])
    # Separate downgrade decision examples, also synthetic.
    downgrade=[
      {'client_profile':'Legacy app that permits HTTP fallback','HSTS_known_or_preloaded':False,'result':'Downgrade accepted in model','sensitive_cleartext_possible':True},
      {'client_profile':'Conforming browser with HSTS policy','HSTS_known_or_preloaded':True,'result':'HTTP blocked / HTTPS required','sensitive_cleartext_possible':False},
    ]
    return rows,events,downgrade

def write_csv(path, rows):
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys()));w.writeheader();w.writerows(rows)

def font(size,bold=False):
    candidates=[r'C:\Windows\Fonts\segoeuib.ttf' if bold else r'C:\Windows\Fonts\segoeui.ttf',r'C:\Windows\Fonts\arialbd.ttf' if bold else r'C:\Windows\Fonts\arial.ttf']
    for fp in candidates:
        try:return ImageFont.truetype(fp,size)
        except OSError:pass
    return ImageFont.load_default()

# visual palette
NAVY='#10243A'; INK='#172B3A'; MUTED='#65788A'; BG='#F3F6FA'; WHITE='#FFFFFF'; BLUE='#2563EB'; TEAL='#0F9D87'; RED='#D94B4B'; GOLD='#D58B16'; PALE='#E8EEF5'; GREEN='#14866D'
def hexrgb(c):return tuple(int(c[i:i+2],16) for i in (1,3,5))
def rounded(d,box,fill,rad=18,outline=None,width=1):d.rounded_rectangle(box,radius=rad,fill=fill,outline=outline,width=width)
def text(d,xy,s,size=20,color=INK,bold=False):d.text(xy,s,font=font(size,bold),fill=color)
def center(d,x,y,s,size=20,color=INK,bold=False):
    f=font(size,bold); bb=d.textbbox((0,0),s,font=f); d.text((x-(bb[2]-bb[0])/2,y),s,font=f,fill=color)

def dashboard(rows):
    W,H=1600,1000; im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im)
    d.rectangle((0,0,W,100),fill=NAVY);text(d,(60,28),'SECURE NETWORKS  /  OFFLINE LAB',18,'#AFC3D6',True);text(d,(60,52),'ARP MITM simulation results',30,WHITE,True)
    text(d,(W-420,43),'COURSE 23CSE336  •  MODEL RUN 336',16,'#C5D2DE',True)
    # metric tiles
    tiles=[('Synthetic hosts',str(len(HOSTS)),'Illustrative finance endpoints',BLUE),('Unsafe HTTP case','8 exposed','Credential field leaks modeled',RED),('DAI-blocked claims','16 drops','Trusted binding policy active',TEAL),('Layered outcome','0 exposed','TLS + DAI + HSTS model',GREEN)]
    for i,(label,val,sub,col) in enumerate(tiles):
        x=60+i*375;rounded(d,(x,130,x+345,260),WHITE,18,'#DCE4EC',2);d.rounded_rectangle((x,130,x+8,260),radius=4,fill=col);text(d,(x+26,151),label,16,MUTED,True);text(d,(x+26,181),val,28,col,True);text(d,(x+26,224),sub,14,MUTED)
    # chart
    rounded(d,(60,290,1010,775),WHITE,18,'#DCE4EC',2);text(d,(90,316),'What changes across network conditions',23,INK,True);text(d,(90,351),'Synthetic affected hosts and clear-text credential exposure',15,MUTED)
    left,top,right,bottom=120,420,955,710
    for val in range(0,9,2):
        y=bottom-int(val/8*(bottom-top));d.line((left,y,right,y),fill='#E4EAF0',width=2);text(d,(83,y-11),str(val),13,MUTED)
    labels=['Baseline','MITM + HTTP','MITM + TLS','DAI + HTTP','Layered']
    for i,row in enumerate(rows):
        cx=190+i*165
        h=int(row['hosts_redirected']/8*(bottom-top));d.rounded_rectangle((cx-30,bottom-h,cx+30,bottom),radius=8,fill=BLUE if i in (1,2) else TEAL if i in (3,4) else '#9AA9B7')
        e=int(row['synthetic_credentials_exposed']/8*(bottom-top));
        if e:d.rounded_rectangle((cx+37,bottom-e,cx+81,bottom),radius=7,fill=RED)
        text(d,(cx-49,bottom+16),labels[i],13,MUTED,True)
    d.rectangle((120,750,150,766),fill=BLUE);text(d,(160,746),'Hosts redirected',13,MUTED);d.rectangle((330,750,360,766),fill=RED);text(d,(370,746),'Credentials exposed',13,MUTED)
    # right-side explanation
    rounded(d,(1040,290,1540,775),WHITE,18,'#DCE4EC',2);text(d,(1075,316),'How to read this run',23,INK,True)
    notes=[('1','No attacker','No ARP claims; no redirection.','#9AA9B7'),('2','MITM + HTTP','All 8 modeled hosts redirect; synthetic clear text exposed.',RED),('3','TLS only','Frames redirect, but payload stays encrypted; metadata and DoS remain.',BLUE),('4','DAI + snooping','Forged claims rejected using trusted bindings.',TEAL),('5','Defense in depth','DAI blocks redirection; TLS/HSTS protect application channel.',GREEN)]
    y=370
    for num,title,desc,col in notes:
        d.ellipse((1075,y,1118,y+43),fill=col);center(d,1096,y+8,num,18,WHITE,True);text(d,(1135,y+1),title,16,INK,True)
        for li,line in enumerate(textwrap.wrap(desc,width=49)[:2]):text(d,(1135,y+24+li*17),line,12,MUTED)
        y+=77
    d.line((60,825,1540,825),fill='#D8E1EA',width=2);text(d,(60,850),'SIMULATED DATA  •  No packets sent  •  No real credentials  •  Results are model outputs, not measured network observations',15,MUTED,True)
    text(d,(60,886),'Deterministic model ID: 336     |     8 hosts     |     3 synthetic sensitive flows / redirected host',14,MUTED)
    im.save(OUT/'01_simulation_results.png')

def frame_diagram():
    W,H=1600,900;im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im)
    d.rectangle((0,0,W,94),fill=NAVY);text(d,(60,28),'PACKET-LEVEL RESULT',18,'#BFD0DF',True);text(d,(60,53),'ARP poisoning changes the Ethernet next hop',28,WHITE,True)
    boxes=[(60,160,750,690),(850,160,1540,690)]
    for box in boxes:rounded(d,box,WHITE,20,'#DCE4EC',2)
    text(d,(100,195),'A  NORMAL',18,BLUE,True);text(d,(890,195),'B  AFTER FALSE ARP MAPPING',18,RED,True)
    # simple topology
    nodes=[(140,290,270,365,'Workstation'),(470,290,600,365,'Gateway'),(830,290,960,365,'Workstation'),(1100,290,1230,365,'Attacker'),(1360,290,1490,365,'Gateway')]
    for x1,y1,x2,y2,label in nodes:rounded(d,(x1,y1,x2,y2),'#EAF1F8',14,'#C8D6E5',2);center(d,(x1+x2)//2,y1+25,label,16,INK,True)
    # lines arrows
    d.line((280,328,455,328),fill=BLUE,width=5);d.polygon([(455,328),(438,319),(438,337)],fill=BLUE)
    d.line((970,328,1085,328),fill=RED,width=5);d.polygon([(1085,328),(1068,319),(1068,337)],fill=RED)
    d.line((1240,328,1345,328),fill=TEAL,width=5);d.polygon([(1345,328),(1328,319),(1328,337)],fill=TEAL)
    text(d,(100,420),'Frame destination MAC',16,MUTED,True);text(d,(100,453),'00:1A:2B:3C:4D:5E  (gateway)',21,BLUE,True)
    text(d,(100,510),'IP source → destination',16,MUTED,True);text(d,(100,543),'192.168.40.51 → 192.168.40.1',21,INK,True)
    text(d,(890,420),'Frame destination MAC',16,MUTED,True);text(d,(890,453),'AA:BB:CC:DD:EE:FF  (attacker)',21,RED,True)
    text(d,(890,510),'IP source → destination',16,MUTED,True);text(d,(890,543),'192.168.40.51 → 192.168.40.1',21,INK,True)
    text(d,(100,618),'Switch sends frame to gateway port.',16,BLUE,True);text(d,(890,618),'Switch sends frame to attacker; relay can preserve session.',16,RED,True)
    text(d,(60,760),'Synthetic illustrative addresses. Only the Ethernet destination MAC changes in this model; the IP header remains intact.',17,MUTED,True)
    im.save(OUT/'02_frame_change.png')
def defense_chart(rows):
    W,H=1600,900;im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im)
    d.rectangle((0,0,W,95),fill=NAVY);text(d,(60,28),'CONTROL COMPARISON',17,'#BFD0DF',True);text(d,(60,53),'Prevention and encryption address different failure points',28,WHITE,True)
    rounded(d,(60,145,1540,760),WHITE,20,'#DCE4EC',2)
    text(d,(100,180),'Modeled outcome by condition',22,INK,True)
    headers=['Condition','Hosts redirected','Credentials exposed','Forged claims dropped','Payload tamper possible']
    x=[100,540,790,1080,1320]
    for xx,label in zip(x,headers):text(d,(xx,235),label,14,MUTED,True)
    d.line((95,270,1505,270),fill='#D8E1EA',width=2)
    for i,row in enumerate(rows):
        y=300+i*82
        if i%2==0:d.rounded_rectangle((92,y-7,1508,y+58),radius=8,fill='#F5F8FB')
        col=RED if int(row['synthetic_credentials_exposed']) else TEAL if row['forged_claims_dropped_by_dai'] else BLUE
        text(d,(105,y+7),row['condition'],16,INK,True)
        for xx,key in zip(x[1:],['hosts_redirected','synthetic_credentials_exposed','forged_claims_dropped_by_dai','application_payload_tampering_possible']):
            val=row[key]; text(d,(xx+20,y+7),str(val),17,col,True)
    text(d,(100,720),'Interpretation: TLS protects the application payload but does not stop Layer 2 redirection; DAI blocks false mappings when its binding policy is correct.',16,MUTED,True)
    im.save(OUT/'03_defense_comparison.png')

def terminal_capture(rows):
    W,H=1500,760;im=Image.new('RGB',(W,H),'#0D1420');d=ImageDraw.Draw(im)
    rounded(d,(40,35,W-40,H-35),'#111B29',22,'#2D4057',2)
    d.ellipse((70,65,86,81),fill='#FF5F57');d.ellipse((98,65,114,81),fill='#FEBC2E');d.ellipse((126,65,142,81),fill='#28C840')
    text(d,(180,58),'secure-networks-lab  /  offline simulation',16,'#AFC2D6',True)
    text(d,(80,125),'$ python run_lab.py',20,'#9FE870',True)
    text(d,(80,173),'SIMULATION COMPLETE - SYNTHETIC DATA ONLY',22,'#72D6C2',True)
    text(d,(80,221),'Condition                       Redirected     Clear-text secrets     DAI drops',17,'#AFC2D6',True)
    d.line((80,258,1410,258),fill='#33465C',width=2)
    y=285
    for row in rows:
        name=row['condition'][:30].ljust(30);red=str(row['hosts_redirected']).rjust(5);secrets=str(row['synthetic_credentials_exposed']).rjust(15);drops=str(row['forged_claims_dropped_by_dai']).rjust(12)
        col='#FF8176' if int(row['synthetic_credentials_exposed']) else '#72D6C2'
        text(d,(80,y),f'{name} {red} {secrets} {drops}',17,col);y+=53
    d.line((80,575,1410,575),fill='#33465C',width=2)
    text(d,(80,605),'No sockets opened. No ARP frames sent. No actual credentials generated or collected.',16,'#F2C879',True)
    text(d,(80,645),'All counts are deterministic teaching-model outputs; run metadata and CSVs are included.',15,'#AFC2D6')
    im.save(OUT/'04_terminal_results.png')

def host_heatmap(rows):
    W,H=1600,850;im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im)
    d.rectangle((0,0,W,100),fill=NAVY)
    text(d,(60,27),'HOST-LEVEL HEATMAP',17,'#BFD0DF',True)
    text(d,(60,54),'Every synthetic endpoint across each modeled condition',27,WHITE,True)
    rounded(d,(60,145,1540,665),WHITE,20,'#DCE4EC',2)
    text(d,(100,180),'Endpoint state by scenario',22,INK,True)
    left=470; top=270; cw=125; ch=67
    for j,host in enumerate(HOSTS):center(d,left+j*cw+cw/2,225,host.rsplit('.',1)[-1],14,MUTED,True)
    states=[('Baseline / no attacker','Normal', '#DCE5EF'),
            ('ARP MITM / HTTP','Exposed',RED),
            ('ARP MITM / TLS validated','Redirected',GOLD),
            ('DAI + snooping / HTTP','Blocked',TEAL),
            ('Layered: DAI + TLS + HSTS','Blocked',GREEN)]
    for i,(label,state,color) in enumerate(states):
        y=top+i*ch
        text(d,(100,y+20),label,15,INK,True)
        for j in range(len(HOSTS)):
            x=left+j*cw
            rounded(d,(x+4,y+3,x+cw-4,y+ch-4),color,9)
            center(d,x+cw/2,y+21,state,13,WHITE if color not in ('#DCE5EF',) else INK,True)
    text(d,(100,630),'Host addresses are synthetic. The same outcome is shown for all eight modeled endpoints by design.',14,MUTED,True)
    legend=[('Normal','#DCE5EF',INK),('Redirected, TLS protected',GOLD,WHITE),('Clear-text exposed',RED,WHITE),('ARP claim blocked',TEAL,WHITE)]
    x=100;y=715
    for label,color,fg in legend:
        rounded(d,(x,y,x+28,y+22),color,5)
        text(d,(x+38,y+2),label,14,MUTED,True)
        x+=300 if len(label)>18 else 220
    text(d,(60,795),'SIMULATED DATA  •  No packets sent  •  State labels summarize model outcomes, not real endpoint observations',14,MUTED,True)
    im.save(OUT/'05_host_scenario_heatmap.png')

def outcome_heatmap(rows):
    W,H=1700,900;im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im)
    d.rectangle((0,0,W,100),fill=NAVY)
    text(d,(60,27),'CONTROL-OUTCOME HEATMAP',17,'#BFD0DF',True)
    text(d,(60,54),'Compare interception, exposure and remaining risk',27,WHITE,True)
    rounded(d,(60,145,1640,735),WHITE,20,'#DCE4EC',2)
    text(d,(100,180),'Modeled outcome intensity',22,INK,True)
    cols=[('Hosts redirected','hosts_redirected',8,'risk'),
          ('Credentials exposed','synthetic_credentials_exposed',8,'risk'),
          ('DAI drops','forged_claims_dropped_by_dai',16,'control'),
          ('Metadata visible','encrypted_flow_metadata_observable',24,'risk'),
          ('Tamper possible','application_payload_tampering_possible',1,'risk'),
          ('DoS possible','availability_disruption_still_possible',1,'risk')]
    x0=485; cw=180; y0=300; rh=76
    for j,(label,_,_,_) in enumerate(cols):
        center(d,x0+j*cw+cw/2,235,label,14,MUTED,True)
    for i,row in enumerate(rows):
        y=y0+i*rh
        text(d,(100,y+20),row['condition'],15,INK,True)
        for j,(_,key,maxv,kind) in enumerate(cols):
            raw=row[key]; value=(1 if str(raw).lower()=='true' else 0) if maxv==1 else int(raw)
            intensity=value/maxv
            if kind=='control':
                light=(225,244,238); dark=(15,157,135)
            else:
                light=(249,235,232); dark=(217,75,75)
            color=tuple(round(light[k]+(dark[k]-light[k])*intensity) for k in range(3))
            x=x0+j*cw
            rounded(d,(x+5,y+3,x+cw-5,y+rh-5),color,9)
            labelval=('Yes' if value else 'No') if maxv==1 else str(value)
            fg=WHITE if intensity>.55 else INK
            center(d,x+cw/2,y+24,labelval,19,fg,True)
    text(d,(100,700),'Risk columns: darker red = higher modeled exposure. DAI column: darker teal = more forged claims rejected.',14,MUTED,True)
    text(d,(60,795),'SIMULATED DATA  •  Count columns use their own fixed scale; Yes/No columns are binary model outcomes.',14,MUTED,True)
    im.save(OUT/'06_control_outcome_heatmap.png')

def main():
    rows,events,downgrade=simulate()
    events.sort(key=lambda row:row[0])
    write_csv(OUT/'scenario_results.csv',rows)
    with (OUT/'event_log.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f);w.writerow(['timestamp_utc','event_type','host_or_device','claimed_ip_or_flow','description','condition']);w.writerows(events)
    write_csv(OUT/'ssl_downgrade_examples.csv',downgrade)
    metadata={'title':'Offline ARP MITM teaching simulation','course':'23CSE336 Secure Networks','synthetic_data':True,'network_traffic_sent':False,'real_credentials_used':False,'model_id':336,'hosts':HOSTS,'gateway_ip':GATEWAY_IP,'gateway_mac':GATEWAY_MAC,'attacker_mac':ATTACKER_MAC,'sensitive_flows_per_redirected_host':FLOWS_PER_HOST,'scope_note':'Illustrative model results, not measurements from Ashwin Holdings or any production network.','run_utc':datetime.now(timezone.utc).isoformat(),'files':['scenario_results.csv','event_log.csv','ssl_downgrade_examples.csv','01_simulation_results.png','02_frame_change.png','03_defense_comparison.png','04_terminal_results.png','05_host_scenario_heatmap.png','06_control_outcome_heatmap.png']}
    (OUT/'run_metadata.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    dashboard(rows);frame_diagram();defense_chart(rows);terminal_capture(rows);host_heatmap(rows);outcome_heatmap(rows)
    print('SIMULATION COMPLETE - SYNTHETIC DATA ONLY')
    print(f"{'Condition':32} {'Redirected':>10} {'Secrets':>10} {'DAI drops':>10}")
    for r in rows:print(f"{r['condition']:32} {r['hosts_redirected']:>10} {r['synthetic_credentials_exposed']:>10} {r['forged_claims_dropped_by_dai']:>10}")
    print('No network packets sent. Results written to',OUT)

if __name__=='__main__':main()


