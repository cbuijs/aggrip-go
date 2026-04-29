// ==========================================================================
// Filename: shared/validation.go
// Version: 1.2.3-20260429
// Date: 2026-04-29 12:26 CEST
// Update Trail:
//   - 1.2.3-20260429: Added missing shared.IsFastIP function for standardized
//                     high-performance IP validation across the tool suite.
//   - 1.2.0-20260429: Migrated TLD dictionaries and structural validation from 
//                     clean-dom/validator.go to centralize DNS rule enforcement.
// Description: Centralized high-performance heuristics and validation utilities.
//              Embeds zero-dependency dictionaries for offline validation.
// ==========================================================================

package shared

import (
	"fmt"
	"net/netip"
	"strings"
)

var (
	activeTLDs      map[string]struct{}
	tldCheckEnabled bool
	hnsTLDsMap      map[string]struct{}
	hnsAllowed      bool
)

// ==========================================================================
// Embedded Zero-Dependency Dictionaries
// Designed for offline, high-speed validation pipelines.
// ==========================================================================

// Handshake (HNS)
// Known registered extensions sourced via NiceNIC
const hnsTLDs = "abo,aboutme,aby,aca,addme,adlt,advisor,afam,afz,ags,agua,ahoy,aj,albums,alto,amg,amigo,amor,ane,annex,aotearoa,apartment,api,arbitrator,artesanal,articles,artificial,assurances,atc,ath,atwork,augmented,baas,badly,bakes,batch,beach,beef,bem,biometric,bitcoinfund,bizdata,blockchaindapps,blogging,bmp,bob,bog,booked,boredapes,bqw,brand,brewery,brokers,browsers,btt,buddhist,byn,c,cabins,cardcollector,cares,catgirl,causes,cerrajero,cheddar,cism,cita,citizenship,ckq,clc,clic,client,clients,cliq,cloudbot,codeschool,coffees,coinnet,comic,comics,commerce,communion,complete,computers,concise,conduct,conductor,conf,connectors,connoisseur,consultancy,cork,corporation,crazy,creations,creativity,creator,crew,croatia,cryp,cryptobets,cryptogamer,cryptoservice,cuba,cycle,cyprus,dais,damn,dan,datamining,daytrade,dean,debtless,decent,decentralize,defi,deficit,degen,den,detour,development,dg,dh,dids,digitalasset,dilate,directive,discounts,discussion,diva,dlt,dly,doge,dogecoin,dojo,dolls,doma,dookie,douchebag,down,downloads,ds,ducktape,duration,dvd,dweb,dy,eathere,economics,economy,edm,egame,elect,electronics,elite,emj,engaged,ep,eporn,ero,estates,eternity,etickets,event,ewallet,ewx,ext,exu,eyecare,ez,fak,fam,faqs,fcb,fd,fe,feeling,fej,fellowship,ffa,fgz,fia,fiji,filters,financialnews,findme,firstname,flat,fmw,follow,foot,forall,fore,freebies,fua,fundraising,fw,fwd,gad,gadget,gdl,ger,gethigh,getreal,getwell,gic,gin,giveaways,gofor,gon,gonow,goth,grandmaster,greatoffers,grow,gruppen,guey,guidance,guz,gvz,gyc,gzp,hack,hackathon,hae,hah,haiti,hardrive,hb,heh,hell,helpdesk,hem,hermanos,hf,hill,hire,hits,hodlr,holding,holidayrental,holidays,hometown,horny,hotelguide,hpp,hsu,hx,ib,ibn,ieh,ifv,ih,ik,ill,iloveu,income,influencer,information,inh,innovator,interest,intro,iny,ioi,ioo,island,ism,isthefuture,italy,iuh,iurl,iw,ize,ja,january,jao,jeh,job,jok,joker,jov,jpg,jpgs,js,jub,jugar,jun,jy,kcx,kennel,keys,kf,kicks,kinetic,kip,kl,knight,knowledge,kq,ks,kv,lars,lausanne,lawexpert,lawoffice,lawsuit,lean,legendary,likeapro,lingo,livestreaming,ljb,lli,lnx,lo,logo,lord,lov,lovesyou,lw,lyf,lz,maestro,magazine,mansion,mediator,medico,mee,ment,merc,mev,micro,mined,mission,mke,moar,mommy,montage,mooning,motherboard,mtl,mvo,mycard,myco,myo,myproxy,myurl,nah,napavalley,nearme,neo,nerdy,nftcartel,nfts,nil,nod,nom,notes,nouns,npm,nuk,numb,nxs,nym,ob,od,oda,often,oh,ohmy,oin,oncam,onewallet,onlinenews,oo,oof,oot,optimize,oq,orb,oslo,ot,oun,owbo,p,paid,pal,pave,pdcst,performer,pest,pgp,picture,pier,pix,piz,places,plaza,ply,pockets,poj,policeman,ppp,praha,premio,premium,presenter,prices,profiles,project,pui,pun,pv,pz,qd,qf,qg,qh,qk,qn,qo,queens,qum,qy,rekt,remember,researcher,resources,rh,rican,rl,rn,rogan,row,rpgs,rumor,runs,rural,russo,rust,rz,saas,sales,samples,say,schooling,sds,secrets,semi,sexblog,sharing,shark,shoppingcart,shortcut,shot,shp,sig,simplicity,sniff,solution,sos,southafrican,sox,spac,specs,squirtfiesta,src,ssl,startup,streamer,sus,swapz,tao,tar,taxfree,techblog,teck,teenager,teepee,tefi,ter,thenerd,tni,token,trader,trans,trekking,tricks,troll,tuber,turtles,tutorial,tx,ud,ue,uf,uge,ultimate,umo,underground,underworld,unit,universe,unlock,use,uui,uzr,valley,vase,vie,viewer,visit,vj,vlog,vq,vuo,wasabi,wave,wc,webartist,webdesigner,websites,wh,whitepaper,wj,wl,won,worldtour,wq,wr,wt,xa,xb,xc,xcam,xf,xi,xk,xr,xxxx,yb,yd,year,yh,yj,yo,yol,yolo,yq,yummy,yx,yzx,zc,zen,zh,zoy,zp,zs,zug,zx,zy"

// OpennNic
const opennicTLDs = "bbs,chan,cyb,dyn,epic,geek,gopher,indy,libre,neo,null,o,oss,oz,parody,pirate"

// IANA/ICANN
const ianaTLDs = "aaa,aarp,abb,abbott,abbvie,abc,able,abogado,abudhabi,ac,academy,accenture,accountant,accountants,aco,actor,ad,ads,adult,ae,aeg,aero,aetna,af,afl,africa,ag,agakhan,agency,ai,aig,airbus,airforce,airtel,akdn,al,alibaba,alipay,allfinanz,allstate,ally,alsace,alstom,am,amazon,americanexpress,americanfamily,amex,amfam,amica,amsterdam,analytics,android,anquan,anz,ao,aol,apartments,app,apple,aq,aquarelle,ar,arab,aramco,archi,army,arpa,art,arte,as,asda,asia,associates,at,athleta,attorney,au,auction,audi,audible,audio,auspost,author,auto,autos,aw,aws,ax,axa,az,azure,ba,baby,baidu,banamex,band,bank,bar,barcelona,barclaycard,barclays,barefoot,bargains,baseball,basketball,bauhaus,bayern,bb,bbc,bbt,bbva,bcg,bcn,bd,be,beats,beauty,beer,berlin,best,bestbuy,bet,bf,bg,bh,bharti,bi,bible,bid,bike,bing,bingo,bio,biz,bj,black,blackfriday,blockbuster,blog,bloomberg,blue,bm,bms,bmw,bn,bnpparibas,bo,boats,boehringer,bofa,bom,bond,boo,book,booking,bosch,bostik,boston,bot,boutique,box,br,bradesco,bridgestone,broadway,broker,brother,brussels,bs,bt,build,builders,business,buy,buzz,bv,bw,by,bz,bzh,ca,cab,cafe,cal,call,calvinklein,cam,camera,camp,canon,capetown,capital,capitalone,car,caravan,cards,care,career,careers,cars,casa,case,cash,casino,cat,catering,catholic,cba,cbn,cbre,cc,cd,center,ceo,cern,cf,cfa,cfd,cg,ch,chanel,channel,charity,chase,chat,cheap,chintai,christmas,chrome,church,ci,cipriani,circle,cisco,citadel,citi,citic,city,ck,cl,claims,cleaning,click,clinic,clinique,clothing,cloud,club,clubmed,cm,cn,co,coach,codes,coffee,college,cologne,com,commbank,community,company,compare,computer,comsec,condos,construction,consulting,contact,contractors,cooking,cool,coop,corsica,country,coupon,coupons,courses,cpa,cr,credit,creditcard,creditunion,cricket,crown,crs,cruise,cruises,cu,cuisinella,cv,cw,cx,cy,cymru,cyou,cz,dad,dance,data,date,dating,datsun,day,dclk,dds,de,deal,dealer,deals,degree,delivery,dell,deloitte,delta,democrat,dental,dentist,desi,design,dev,dhl,diamonds,diet,digital,direct,directory,discount,discover,dish,diy,dj,dk,dm,dnp,do,docs,doctor,dog,domains,dot,download,drive,dtv,dubai,dupont,durban,dvag,dvr,dz,earth,eat,ec,eco,edeka,edu,education,ee,eg,email,emerck,energy,engineer,engineering,enterprises,epson,equipment,er,ericsson,erni,es,esq,estate,et,eu,eurovision,eus,events,exchange,expert,exposed,express,extraspace,fage,fail,fairwinds,faith,family,fan,fans,farm,farmers,fashion,fast,fedex,feedback,ferrari,ferrero,fi,fidelity,fido,film,final,finance,financial,fire,firestone,firmdale,fish,fishing,fit,fitness,fj,fk,flickr,flights,flir,florist,flowers,fly,fm,fo,foo,food,football,ford,forex,forsale,forum,foundation,fox,fr,free,fresenius,frl,frogans,frontier,ftr,fujitsu,fun,fund,furniture,futbol,fyi,ga,gal,gallery,gallo,gallup,game,games,gap,garden,gay,gb,gbiz,gd,gdn,ge,gea,gent,genting,george,gf,gg,ggee,gh,gi,gift,gifts,gives,giving,gl,glass,gle,global,globo,gm,gmail,gmbh,gmo,gmx,gn,godaddy,gold,goldpoint,golf,goodyear,goog,google,gop,got,gov,gp,gq,gr,grainger,graphics,gratis,green,gripe,grocery,group,gs,gt,gu,gucci,guge,guide,guitars,guru,gw,gy,hair,hamburg,hangout,haus,hbo,hdfc,hdfcbank,health,healthcare,help,helsinki,here,hermes,hiphop,hisamitsu,hitachi,hiv,hk,hkt,hm,hn,hockey,holdings,holiday,homedepot,homegoods,homes,homesense,honda,horse,hospital,host,hosting,hot,hotels,hotmail,house,how,hr,hsbc,ht,hu,hughes,hyatt,hyundai,ibm,icbc,ice,icu,id,ie,ieee,ifm,ikano,il,im,imamat,imdb,immo,immobilien,in,inc,industries,infiniti,info,ing,ink,institute,insurance,insure,int,international,intuit,investments,io,ipiranga,iq,ir,irish,is,ismaili,ist,istanbul,it,itau,itv,jaguar,java,jcb,je,jeep,jetzt,jewelry,jio,jll,jm,jmp,jnj,jo,jobs,joburg,jot,joy,jp,jpmorgan,jprs,juegos,juniper,kaufen,kddi,ke,kerryhotels,kerryproperties,kfh,kg,kh,ki,kia,kids,kim,kindle,kitchen,kiwi,km,kn,koeln,komatsu,kosher,kp,kpmg,kpn,kr,krd,kred,kuokgroup,kw,ky,kyoto,kz,la,lacaixa,lamborghini,lamer,land,landrover,lanxess,lasalle,lat,latino,latrobe,law,lawyer,lb,lc,lds,lease,leclerc,lefrak,legal,lego,lexus,lgbt,li,lidl,life,lifeinsurance,lifestyle,lighting,like,lilly,limited,limo,lincoln,link,live,living,lk,llc,llp,loan,loans,locker,locus,lol,london,lotte,lotto,love,lpl,lplfinancial,lr,ls,lt,ltd,ltda,lu,lundbeck,luxe,luxury,lv,ly,ma,madrid,maison,makeup,man,management,mango,map,market,marketing,markets,marriott,marshalls,mattel,mba,mc,mckinsey,md,me,med,media,meet,melbourne,meme,memorial,men,menu,merck,merckmsd,mg,mh,miami,microsoft,mil,mini,mint,mit,mitsubishi,mk,ml,mlb,mls,mm,mma,mn,mo,mobi,mobile,moda,moe,moi,mom,monash,money,monster,mormon,mortgage,moscow,moto,motorcycles,mov,movie,mp,mq,mr,ms,msd,mt,mtn,mtr,mu,museum,music,mv,mw,mx,my,mz,na,nab,nagoya,name,navy,nba,nc,ne,nec,net,netbank,netflix,network,neustar,new,news,next,nextdirect,nexus,nf,nfl,ng,ngo,nhk,ni,nico,nike,nikon,ninja,nissan,nissay,nl,no,nokia,norton,now,nowruz,nowtv,np,nr,nra,nrw,ntt,nu,nyc,nz,obi,observer,office,okinawa,olayan,olayangroup,ollo,om,omega,one,ong,onl,online,ooo,open,oracle,orange,org,organic,origins,osaka,otsuka,ott,ovh,pa,page,panasonic,paris,pars,partners,parts,party,pay,pccw,pe,pet,pf,pfizer,pg,ph,pharmacy,phd,philips,phone,photo,photography,photos,physio,pics,pictet,pictures,pid,pin,ping,pink,pioneer,pizza,pk,pl,place,play,playstation,plumbing,plus,pm,pn,pnc,pohl,poker,politie,porn,post,pr,praxi,press,prime,pro,prod,productions,prof,progressive,promo,properties,property,protection,pru,prudential,ps,pt,pub,pw,pwc,py,qa,qpon,quebec,quest,racing,radio,re,read,realestate,realtor,realty,recipes,red,redumbrella,rehab,reise,reisen,reit,reliance,ren,rent,rentals,repair,report,republican,rest,restaurant,review,reviews,rexroth,rich,richardli,ricoh,ril,rio,rip,ro,rocks,rodeo,rogers,room,rs,rsvp,ru,rugby,ruhr,run,rw,rwe,ryukyu,sa,saarland,safe,safety,sakura,sale,salon,samsclub,samsung,sandvik,sandvikcoromant,sanofi,sap,sarl,sas,save,saxo,sb,sbi,sbs,sc,scb,schaeffler,schmidt,scholarships,school,schule,schwarz,science,scot,sd,se,search,seat,secure,security,seek,select,sener,services,seven,sew,sex,sexy,sfr,sg,sh,shangrila,sharp,shell,shia,shiksha,shoes,shop,shopping,shouji,show,si,silk,sina,singles,site,sj,sk,ski,skin,sky,skype,sl,sling,sm,smart,smile,sn,sncf,so,soccer,social,softbank,software,sohu,solar,solutions,song,sony,soy,spa,space,sport,spot,sr,srl,ss,st,stada,staples,star,statebank,statefarm,stc,stcgroup,stockholm,storage,store,stream,studio,study,style,su,sucks,supplies,supply,support,surf,surgery,suzuki,sv,swatch,swiss,sx,sy,sydney,systems,sz,tab,taipei,talk,taobao,target,tatamotors,tatar,tattoo,tax,taxi,tc,tci,td,tdk,team,tech,technology,tel,temasek,tennis,teva,tf,tg,th,thd,theater,theatre,tiaa,tickets,tienda,tips,tires,tirol,tj,tjmaxx,tjx,tk,tkmaxx,tl,tm,tmall,tn,to,today,tokyo,tools,top,toray,toshiba,total,tours,town,toyota,toys,tr,trade,trading,training,travel,travelers,travelersinsurance,trust,trv,tt,tube,tui,tunes,tushu,tv,tvs,tw,tz,ua,ubank,ubs,ug,uk,unicom,university,uno,uol,ups,us,uy,uz,va,vacations,vana,vanguard,vc,ve,vegas,ventures,verisign,versicherung,vet,vg,vi,viajes,video,vig,viking,villas,vin,vip,virgin,visa,vision,viva,vivo,vlaanderen,vn,vodka,volvo,vote,voting,voto,voyage,vu,wales,walmart,walter,wang,wanggou,watch,watches,weather,weatherchannel,webcam,weber,website,wed,wedding,weibo,weir,wf,whoswho,wien,wiki,williamhill,win,windows,wine,winners,wme,woodside,work,works,world,wow,ws,wtc,wtf,xbox,xerox,xihuan,xin,xn--11b4c3d,xn--1ck2e1b,xn--1qqw23a,xn--2scrj9c,xn--30rr7y,xn--3bst00m,xn--3ds443g,xn--3e0b707e,xn--3hcrj9c,xn--3pxu8k,xn--42c2d9a,xn--45br5cyl,xn--45brj9c,xn--45q11c,xn--4dbrk0ce,xn--4gbrim,xn--54b7fta0cc,xn--55qw42g,xn--55qx5d,xn--5su34j936bgsg,xn--5tzm5g,xn--6frz82g,xn--6qq986b3xl,xn--80adxhks,xn--80ao21a,xn--80aqecdr1a,xn--80asehdb,xn--80aswg,xn--8y0a063a,xn--90a3ac,xn--90ae,xn--90ais,xn--9dbq2a,xn--9et52u,xn--9krt00a,xn--b4w605ferd,xn--bck1b9a5dre4c,xn--c1avg,xn--c2br7g,xn--cck2b3b,xn--cckwcxetd,xn--cg4bki,xn--clchc0ea0b2g2a9gcd,xn--czr694b,xn--czrs0t,xn--czru2d,xn--d1acj3b,xn--d1alf,xn--e1a4c,xn--eckvdtc9d,xn--efvy88h,xn--fct429k,xn--fhbei,xn--fiq228c5hs,xn--fiq64b,xn--fiqs8s,xn--fiqz9s,xn--fjq720a,xn--flw351e,xn--fpcrj9c3d,xn--fzc2c9e2c,xn--fzys8d69uvgm,xn--g2xx48c,xn--gckr3f0f,xn--gecrj9c,xn--gk3at1e,xn--h2breg3eve,xn--h2brj9c,xn--h2brj9c8c,xn--hxt814e,xn--i1b6b1a6a2e,xn--imr513n,xn--io0a7i,xn--j1aef,xn--j1amh,xn--j6w193g,xn--jlq480n2rg,xn--jvr189m,xn--kcrx77d1x4a,xn--kprw13d,xn--kpry57d,xn--kput3i,xn--l1acc,xn--lgbbat1ad8j,xn--mgb9awbf,xn--mgba3a3ejt,xn--mgba3a4f16a,xn--mgba7c0bbn0a,xn--mgbaam7a8h,xn--mgbab2bd,xn--mgbah1a3hjkrd,xn--mgbai9azgqp6j,xn--mgbayh7gpa,xn--mgbbh1a,xn--mgbbh1a71e,xn--mgbc0a9azcg,xn--mgbca7dzdo,xn--mgbcpq6gpa1a,xn--mgberp4a5d4ar,xn--mgbgu82a,xn--mgbi4ecexp,xn--mgbpl2fh,xn--mgbt3dhd,xn--mgbtx2b,xn--mgbx4cd0ab,xn--mix891f,xn--mk1bu44c,xn--mxtq1m,xn--ngbc5azd,xn--ngbe9e0a,xn--ngbrx,xn--node,xn--nqv7f,xn--nqv7fs00ema,xn--nyqy26a,xn--o3cw4h,xn--ogbpf8fl,xn--otu796d,xn--p1acf,xn--p1ai,xn--pgbs0dh,xn--pssy2u,xn--q7ce6a,xn--q9jyb4c,xn--qcka1pmc,xn--qxa6a,xn--qxam,xn--rhqv96g,xn--rovu88b,xn--rvc1e0am3e,xn--s9brj9c,xn--ses554g,xn--t60b56a,xn--tckwe,xn--tiq49xqyj,xn--unup4y,xn--vermgensberater-ctb,xn--vermgensberatung-pwb,xn--vhquv,xn--vuq861b,xn--w4r85el8fhu5dnra,xn--w4rs40l,xn--wgbh1c,xn--wgbl6a,xn--xhq521b,xn--xkc2al3hye2a,xn--xkc2dl3a5ee0h,xn--y9a3aq,xn--yfro4i67o,xn--ygbi2ammx,xn--zfr164b,xxx,xyz,yachts,yahoo,yamaxun,yandex,ye,yodobashi,yoga,yokohama,you,youtube,yt,yun,za,zappos,zara,zero,zip,zm,zone,zuerich,zw"

// InitTLDValidator parses the configuration and loads the appropriate zero-dependency 
// dictionaries into memory for O(1) high-speed validation lookups natively.
func InitTLDValidator(config string, verbose bool) {
	activeTLDs = make(map[string]struct{})
	hnsTLDsMap = make(map[string]struct{})

	// Pre-load Handshake TLDs universally into isolated map. 
	// Crucial for trailing-slash validations regardless of standard TLD checks.
	for _, t := range strings.Split(hnsTLDs, ",") {
		hnsTLDsMap[t] = struct{}{}
	}

	cfg := strings.ToLower(config)

	// Keep track if HNS is conceptually authorized by the config (via explicit inclusion or disabled limits)
	if strings.Contains(cfg, "hns") || strings.Contains(cfg, "all") || strings.Contains(cfg, "disable") {
		hnsAllowed = true
	} else {
		hnsAllowed = false
	}

	// If disabled or all is specified, we strictly fallback to alphanumeric 
	// RFC structural checks instead of performing dictionary matching natively.
	if strings.Contains(cfg, "disable") || strings.Contains(cfg, "all") {
		tldCheckEnabled = false
		LogMsg(verbose, "TLD Dictionary Validation: DISABLED (Fallback to Strict Structural Validation)")
		return
	}

	tldCheckEnabled = true
	loaded := []string{}

	if strings.Contains(cfg, "iana") {
		for _, t := range strings.Split(ianaTLDs, ",") {
			activeTLDs[t] = struct{}{}
		}
		loaded = append(loaded, "IANA")
	}

	if strings.Contains(cfg, "opennic") {
		for _, t := range strings.Split(opennicTLDs, ",") {
			activeTLDs[t] = struct{}{}
		}
		loaded = append(loaded, "OpenNIC")
	}

	if strings.Contains(cfg, "hns") {
		for k := range hnsTLDsMap {
			activeTLDs[k] = struct{}{}
		}
		loaded = append(loaded, "Handshake (HNS)")
	}

	if len(loaded) > 0 {
		LogMsg(verbose, fmt.Sprintf("TLD Dictionary Validation: ENABLED (%s)", strings.Join(loaded, ", ")))
	} else {
		LogMsg(verbose, "TLD Dictionary Validation: DISABLED (No valid lists provided)")
		tldCheckEnabled = false
	}
}

// IsHNSTLD safely checks if a given TLD natively exists within the Handshake registry.
// Strictly guards validations to ensure the user config technically allowed HNS parsing.
func IsHNSTLD(tld string) bool {
	if !hnsAllowed {
		return false
	}
	_, exists := hnsTLDsMap[strings.ToLower(tld)]
	return exists
}

// ValidateDomain unifies structural bound checking, strict RFC enforcement, and 
// dictionary lookups into a single precise evaluator returning detailed error states.
func ValidateDomain(domain string, lessStrict bool, allowTLD bool) error {
	if len(domain) == 0 || len(domain) > 253 {
		return fmt.Errorf("length out of bounds (1-253)")
	}

	// Fast structural edge bounds
	if domain[0] == '.' || domain[len(domain)-1] == '.' {
		return fmt.Errorf("starts or ends with a dot")
	}

	parts := strings.Split(domain, ".")
	if !allowTLD && len(parts) < 2 {
		return fmt.Errorf("missing TLD (isolated keyword)")
	}
	if len(parts) == 0 {
		return fmt.Errorf("empty domain string")
	}

	for _, part := range parts {
		l := len(part)
		if l == 0 || l > 63 {
			return fmt.Errorf("label length out of bounds (1-63)")
		}

		// Blocks cannot start or end with standard hyphens per RFC
		if part[0] == '-' || part[l-1] == '-' {
			return fmt.Errorf("label starts or ends with hyphen")
		}

		// Enforce underscore boundary blocks unless less-strict is actively toggled
		if !lessStrict && (part[0] == '_' || part[l-1] == '_') {
			return fmt.Errorf("label contains strict boundary underscores")
		}

		for j := 0; j < l; j++ {
			c := part[j]
			valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'

			// Open regex parity boundaries for legacy non-compliant feeds
			if !valid && lessStrict {
				if c == '_' || c == '*' {
					valid = true
				}
			}
			if !valid {
				return fmt.Errorf("contains invalid characters")
			}
		}
	}

	// --------------------------------------------------------------------------
	// Advanced TLD Validation Phase
	// --------------------------------------------------------------------------

	tld := parts[len(parts)-1]

	// 1. Strict RFC Fallback: Ensure the TLD isn't entirely numeric (e.g., 201.22.83)
	isNumeric := true
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			isNumeric = false
			break
		}
	}
	if isNumeric {
		return fmt.Errorf("strict RFC violation (all-numeric TLD)")
	}

	// 2. Dictionary Lookups: Verify the parsed TLD against enterprise lists securely
	if tldCheckEnabled {
		if _, exists := activeTLDs[strings.ToLower(tld)]; !exists {
			return fmt.Errorf("unregistered/invalid TLD format")
		}
	}

	return nil
}

// IsFastIP runs a fast heuristic check using netip to ensure valid IP structures
// (IPv4/IPv6). It bypasses regular expressions for high-performance memory-safe 
// execution natively. Acts as a standard alias to IsFastIPStrict.
func IsFastIP(token string) bool {
	return IsFastIPStrict(token)
}

// IsFastIPStrict runs a strict heuristic check using netip to ensure 
// valid IP structures (IPv4/IPv6). Used inherently by clean-dom.
func IsFastIPStrict(token string) bool {
	if len(token) == 0 {
		return false
	}
	c := token[0]
	if (c >= '0' && c <= '9') || c == ':' {
		_, err := netip.ParseAddr(token)
		return err == nil
	}
	return false
}

// IsIPHeuristic runs a highly optimized heuristic to skip pure text blocks
// preventing the system from running expensive IP-parsing exceptions.
// Permits dashes '-' explicitly for IP range parsing natively.
func IsIPHeuristic(token string) bool {
	if len(token) == 0 {
		return false
	}
	c := token[0]
	return (c >= '0' && c <= '9') || c == ':' || c == '-'
}

// IsPlausibleDomain is a high-speed pre-ingestion check to silently drop obvious 
// non-domain garbage (like URLs, regexes, paths from Adblock lists) before they 
// pollute memory or trigger structural validation logs natively.
func IsPlausibleDomain(domain string) bool {
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '*' {
			continue
		}
		return false
	}
	return true
}

// IsValidDomain performs high-speed byte-level validation without regex overhead cleanly.
// Strictly restricts payloads to alphanumeric, hyphens, and periods.
func IsValidDomain(b []byte, lessStrict bool) bool {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
			continue
		}
		if lessStrict && (c == '_' || c == '*') {
			continue
		}
		return false
	}
	return true
}

