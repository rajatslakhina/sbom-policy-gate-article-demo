#!/usr/bin/env python3
"""Visuals for the 2026-09-24 article (Swift 6.4 as a governance release / SBOM gate).
Every number drawn here is pinned by SampleGateTests in
github.com/rajatslakhina/sbom-policy-gate-article-demo (swift test 24/24, Swift 6.0.3).
The sample PR is constructed and the images say so."""
import sys
from PIL import Image, ImageDraw, ImageFont
OUT=sys.argv[1]
F="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"; FB="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FM="/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"; FMB="/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
INK=(22,24,29); MUTED=(110,116,128); LINE=(214,218,226); PAPER=(248,247,244); CARD=(255,255,255)
RED=(183,28,40); AMBER=(176,106,8); GRAY=(96,102,114); GREEN=(26,122,78); BLUE=(0,81,184)
REDL=(251,231,233); AMBERL=(252,240,214); GRAYL=(236,238,241); BLUEL=(228,236,250); GREENL=(226,244,234)
def f(p,s): return ImageFont.truetype(p,s)
def card(d,b,r=16,fill=CARD,outline=LINE,w=2): d.rounded_rectangle(b,radius=r,fill=fill,outline=outline,width=w)
def chip(d,x,y,label,fg,bg,font):
    w=d.textlength(label,font=font); d.rounded_rectangle((x,y,x+w+24,y+34),radius=17,fill=bg); d.text((x+12,y+6),label,font=font,fill=fg); return x+w+24

PINS=[("retry-kit","+ 0.3.1  (new)"),("swift-asn1","1.3.0 → 1.4.0"),("swift-async-algorithms","+ 1.0.4  (new)"),
      ("swift-crypto","3.8.0 → 4.0.0"),("swift-log","1.6.1 → 9f2c41d  (location changed)")]
FIND=[("BLOCK","UNTRUSTED_SOURCE","retry-kit"),("BLOCK","SOURCE_MOVED","swift-log"),
      ("REVIEW","NEW_PACKAGE","retry-kit"),("REVIEW","BREAKING_BUMP","swift-crypto"),
      ("REVIEW","REVISION_PIN","swift-log"),("REVIEW","NEWLY_SHIPPED","swift-snapshot-testing"),
      ("INFO","COMPATIBLE_BUMP","swift-asn1"),("INFO","NEW_PACKAGE","swift-async-algorithms")]
SEV={"BLOCK":(RED,REDL),"REVIEW":(AMBER,AMBERL),"INFO":(GRAY,GRAYL)}

# ---------- header 1400x700 ----------
W,H=1400,700; im=Image.new("RGB",(W,H),(18,22,30)); d=ImageDraw.Draw(im)
d.text((70,64),"SWIFT 6.4  ·  SE-0509  ·  CYCLONEDX 1.7",font=f(FB,22),fill=(140,170,230))
d.text((70,110),"Your lockfile lists pins.",font=f(FB,58),fill=(245,246,248))
d.text((70,182),"Your SBOM knows what ships.",font=f(FB,58),fill=(255,196,92))
# left card: lockfile
card(d,(70,300,660,630),fill=(28,33,44),outline=(58,66,84))
d.text((96,322),"Package.resolved diff",font=f(FB,24),fill=(220,224,232))
d.text((96,356),"5 pins changed",font=f(F,20),fill=(150,158,172))
y=398
for name,ch in PINS:
    d.text((96,y),name,font=f(FMB,19),fill=(200,206,216)); d.text((360,y),ch.split("  ")[0],font=f(FM,19),fill=(150,158,172)); y+=42
# right card: gate
card(d,(720,300,1330,630),fill=(28,33,44),outline=(58,66,84))
d.text((746,322),"SBOM gate, same PR",font=f(FB,24),fill=(220,224,232))
d.text((746,356),"8 findings · 6 packages",font=f(F,20),fill=(150,158,172))
d.text((746,398),"BLOCKED",font=f(FB,46),fill=(255,110,110))
x=746
x=chip(d,x,470,"BLOCK 2",(255,140,140),(70,30,36),f(FB,18))+10
x=chip(d,x,470,"REVIEW 4",(255,196,92),(70,54,24),f(FB,18))+10
chip(d,x,470,"INFO 2",(190,196,206),(52,58,70),f(FB,18))
d.text((746,532),"swift-snapshot-testing: no pin changed,",font=f(FM,17),fill=(255,196,92))
d.text((746,558),"now linked by StorefrontKit",font=f(FM,17),fill=(255,196,92))
d.text((70,660),"Constructed sample PR · numbers pinned by the demo's tests · github.com/rajatslakhina/sbom-policy-gate-article-demo",font=f(F,15),fill=(120,128,142))
im.save(OUT+"/2026-09-24-swift-64-sbom-gate-header.png")

# ---------- diagram 1600x960 ----------
W,H=1600,1000; im=Image.new("RGB",(W,H),PAPER); d=ImageDraw.Draw(im)
d.text((60,44),"One agent PR, two reviews",font=f(FB,40),fill=INK)
d.text((60,100),"PR “Retry image loads on flaky networks” (constructed). Left: what the lockfile diff shows. Right: what the SBOM gate reports.",font=f(F,20),fill=MUTED)
card(d,(60,160,640,900))
d.text((88,186),"Package.resolved",font=f(FB,28),fill=INK); d.text((88,226),"lists pins · 5 changed",font=f(F,19),fill=MUTED)
y=286
for name,ch in PINS:
    card(d,(88,y,612,y+72),r=10,fill=(252,252,251))
    d.text((108,y+12),name,font=f(FMB,20),fill=INK); d.text((108,y+40),ch,font=f(FM,17),fill=MUTED); y+=88
d.text((88,y+14),"swift-snapshot-testing: nothing to see",font=f(FM,18),fill=(170,174,182))
d.text((88,y+42),"(its pin did not change)",font=f(FM,18),fill=(170,174,182))
card(d,(700,160,1540,900))
d.text((728,186),"SBOMGate.evaluate(base:head:policy:)",font=f(FMB,24),fill=INK)
d.text((728,226),"reads product → product edges · 8 findings · verdict: BLOCKED",font=f(F,19),fill=MUTED)
y=276
for sev,rule,pkg in FIND:
    fg,bg=SEV[sev]; hl = rule=="NEWLY_SHIPPED"
    card(d,(728,y,1512,y+60),r=10,fill=bg if hl else (252,252,251),outline=fg if hl else LINE,w=3 if hl else 2)
    d.text((748,y+17),sev,font=f(FB,18),fill=fg); d.text((850,y+17),rule,font=f(FMB,18),fill=INK); d.text((1100,y+17),pkg,font=f(FM,18),fill=INK)
    y+=68
d.text((728,y+8),"snapshot path: StorefrontKit → swift-snapshot-testing:SnapshotTesting",font=f(FM,16),fill=AMBER)
d.text((728,y+34),"asn1 path: StorefrontKit → swift-crypto:_CryptoExtras → swift-asn1:SwiftASN1",font=f(FM,16),fill=GRAY)
d.text((60,930),"Only the SBOM carries which product links which package (SE-0509's stated motivation). Sample SBOMs are constructed in SE-0509's shape,",font=f(F,17),fill=MUTED)
d.text((60,956),"not produced by a real SwiftPM 6.4 run. Counts pinned by SampleGateTests · github.com/rajatslakhina/sbom-policy-gate-article-demo",font=f(F,17),fill=MUTED)
im.save(OUT+"/2026-09-24-swift-64-sbom-gate-diagram.png")
print("ok")
