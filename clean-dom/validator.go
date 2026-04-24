/*
==========================================================================
Filename: clean-dom/validator.go
Version: 1.1.0-20260424
Date: 2026-04-24 09:16 CEST
Description: Handles strict and lenient structural boundaries, RFC 
             enforcement, embedded TLD dictionary mapping, and 
             low-level string validation protocols.
==========================================================================
*/

package main

import (
	"fmt"
	"net/netip"
	"strings"
)

var (
	activeTLDs      map[string]struct{}
	tldCheckEnabled bool
)

// InitTLDValidator parses the configuration and loads the appropriate zero-dependency 
// dictionaries into memory for O(1) high-speed validation lookups natively.
func InitTLDValidator(config string) {
	activeTLDs = make(map[string]struct{})
	cfg := strings.ToLower(config)

	// If Handshake (HNS) or disabled is specified, we strictly fallback to alphanumeric 
	// RFC structural checks because HNS supports any valid string mathematically.
	if strings.Contains(cfg, "disable") || strings.Contains(cfg, "hns") || strings.Contains(cfg, "all") {
		tldCheckEnabled = false
		logMsg("TLD Dictionary Validation: DISABLED (Fallback to Strict Structural Validation)")
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

	if len(loaded) > 0 {
		logMsg(fmt.Sprintf("TLD Dictionary Validation: ENABLED (%s)", strings.Join(loaded, ", ")))
	} else {
		logMsg("TLD Dictionary Validation: DISABLED (No valid lists provided)")
		tldCheckEnabled = false
	}
}

// isFastIP runs a rapid heuristic bypass checking if a token resembles an IP.
func isFastIP(token string) bool {
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

// isPlausibleDomain is a high-speed pre-ingestion check to silently drop obvious 
// non-domain garbage (like URLs, regexes, paths from Adblock lists) before they 
// pollute memory or trigger structural validation logs natively.
func isPlausibleDomain(domain string) bool {
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '*' {
			continue
		}
		return false
	}
	return true
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

// getParents yields a slice of domains traveling bottom-up toward the apex natively.
func getParents(domain string) []string {
	var parents []string
	for {
		parents = append(parents, domain)
		idx := strings.IndexByte(domain, '.')
		if idx == -1 {
			break
		}
		// Safely advance past the matched dot
		domain = domain[idx+1:]
	}
	return parents
}

// reverseStr performs a rapid rune-level reverse string operation for O(N log N) deduplication sorting.
func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// extractDomainForSort strictly pulls the root domain from a string array index safely handling comments
func extractDomainForSort(item string) string {
	if strings.HasPrefix(item, "#") {
		clean := strings.TrimSpace(strings.TrimPrefix(item, "#"))
		return strings.SplitN(clean, " - ", 2)[0]
	}
	return item
}

// ==========================================================================
// Embedded Zero-Dependency Dictionaries
// Designed for offline, high-speed validation pipelines.
// ==========================================================================

const opennicTLDs = "bbs,chan,cyb,dyn,epic,geek,gopher,indy,libre,neo,null,o,oss,oz,parody,pirate"

// Highly compressed matrix representing ~1400 valid IANA Top Level Domains
const ianaTLDs = "com,net,org,edu,gov,mil,int,arpa,aero,asia,biz,cat,coop,info,jobs,mobi,museum,name,post,pro,tel,travel,xxx,ac,ad,ae,af,ag,ai,al,am,an,ao,aq,ar,as,at,au,aw,ax,az,ba,bb,bd,be,bf,bg,bh,bi,bj,bm,bn,bo,br,bs,bt,bv,bw,by,bz,ca,cc,cd,cf,cg,ch,ci,ck,cl,cm,cn,co,cr,cu,cv,cw,cx,cy,cz,de,dj,dk,dm,do,dz,ec,ee,eg,er,es,et,eu,fi,fj,fk,fm,fo,fr,ga,gb,gd,ge,gf,gg,gh,gi,gl,gm,gn,gp,gq,gr,gs,gt,gu,gw,gy,hk,hm,hn,hr,ht,hu,id,ie,il,im,in,io,iq,ir,is,it,je,jm,jo,jp,ke,kg,kh,ki,km,kn,kp,kr,kw,ky,kz,la,lb,lc,li,lk,lr,ls,lt,lu,lv,ly,ma,mc,md,me,mg,mh,mk,ml,mm,mn,mo,mp,mq,mr,ms,mt,mu,mv,mw,mx,my,mz,na,nc,ne,nf,ng,ni,nl,no,np,nr,nu,nz,om,pa,pe,pf,pg,ph,pk,pl,pm,pn,pr,ps,pt,pw,py,qa,re,ro,rs,ru,rw,sa,sb,sc,sd,se,sg,sh,si,sj,sk,sl,sm,sn,so,sr,ss,st,su,sv,sx,sy,sz,tc,td,tf,tg,th,tj,tk,tl,tm,tn,to,tr,tt,tv,tw,tz,ua,ug,uk,us,uy,uz,va,vc,ve,vg,vi,vn,vu,wf,ws,ye,yt,za,zm,zw,aaa,aarp,abarth,abb,abbott,abbvie,abc,able,abogado,abudhabi,academy,accenture,accountant,accountants,aco,actor,ads,adult,aeg,aetna,afl,africa,agakhan,agency,aig,airbus,airforce,airtel,akdn,alfaromeo,alibaba,alipay,allfinanz,allstate,ally,alsace,alstom,amazon,americanexpress,americanfamily,amex,amfam,amica,amsterdam,analytics,android,anquan,anz,aol,apartments,app,apple,aquarelle,arab,aramco,archi,army,art,arte,asda,associates,athletic,audi,audible,audio,auspost,author,auto,autos,avianca,aws,axa,azure,baby,baidu,banamex,bananarepublic,band,bank,bar,barcelona,barclaycard,barclays,barefoot,bargains,baseball,basketball,bauhaus,bayern,bbc,bbt,bbva,bcg,bcn,beats,beauty,beer,bentley,berlin,best,bestbuy,bet,bharti,bible,bid,bike,bing,bingo,bio,black,blackfriday,blockbuster,blog,bloomberg,blue,bms,bmw,bnpparams,boats,boehringer,bofa,bom,bond,boo,book,booking,bosch,bostik,boston,bot,boutique,box,bradesco,bridgestone,broadway,broker,brother,brussels,build,builders,business,buy,buzz,bzh,cab,cafe,cal,call,calvinklein,cam,camera,camp,cancerresearch,canon,capetown,capital,capitalone,car,caravan,cards,care,career,careers,cars,casa,case,cash,casino,catering,catholic,cba,cbn,cbre,cbs,center,ceo,cern,cfa,cfd,chanel,channel,charity,chase,chat,cheap,chintai,christmas,chrome,church,cipriani,circle,cisco,citadel,citi,citic,city,cityeats,claims,cleaning,click,clinic,clinique,clothing,cloud,club,clubmed,coach,codes,coffee,college,cologne,comcast,commbank,community,company,compare,computer,comsec,condos,construction,consulting,contact,contractors,cooking,cookingchannel,cool,corsica,country,coupon,coupons,courses,cpa,credit,creditcard,creditunion,cricket,crown,crs,cruise,cruises,cuisinella,cymru,cyou,dabur,dad,dance,data,date,dating,datsun,day,dclk,dds,deal,dealer,deals,degree,delivery,dell,deloitte,delta,democrat,dental,dentist,desi,design,dev,dhl,diamonds,diet,digital,direct,directory,discount,discover,dish,diy,dnp,docs,doctor,dog,domains,dot,download,drive,dtv,dubai,dunlop,dupont,durban,dvag,dvr,earth,eat,eco,edeka,education,email,emerck,energy,engineer,engineering,enterprises,epson,equipment,ericsson,erni,esq,estate,etisalat,eurovision,eus,events,exchange,expert,exposed,express,extraspace,fage,fail,fairwinds,faith,family,fan,fans,farm,farmers,fashion,fast,fedex,feedback,ferrari,ferrero,fiat,fidelity,fido,film,final,finance,financial,fire,firestone,firmdale,fish,fishing,fit,fitness,flickr,flights,flir,florist,flowers,fly,foo,food,foodnetwork,football,ford,forex,forsale,forum,foundation,fox,free,fresenius,frl,frogans,frontdoor,frontier,ftr,fujitsu,fund,furniture,futbol,fyi,gal,gallery,gallo,gallup,game,games,gap,garden,gay,gbiz,gdn,gea,gent,genting,george,ggee,gift,gifts,gives,giving,glass,gle,global,globo,gmail,gmbh,gmo,gmx,godaddy,gold,goldpoint,golf,goo,goodyear,goog,google,gop,got,grainger,graphics,gratis,green,gripe,grocery,group,gucci,guge,guide,guitars,guru,hair,hamburg,hangout,haus,hbo,hdfc,hdfcbank,health,healthcare,help,helsinki,here,hermes,hgtv,hiphop,hisamitsu,hitachi,hiv,hkt,hockey,holdings,holiday,homedepot,homegoods,homes,homesense,honda,horse,hospital,host,hosting,hot,hoteles,hotels,hotmail,house,how,hsbc,hughes,hyatt,hyundai,ibm,icbc,ice,icu,ieee,ifm,ikano,llc,imamat,imdb,immo,immobilien,inc,industries,infiniti,ing,ink,institute,insurance,insure,international,intuit,investments,ipiranga,irish,iselect,ismaili,ist,istanbul,itau,itv,iveco,jaguar,java,jcb,jeep,jetzt,jewelry,jio,jll,jmp,jnj,jot,joy,jpmorgan,jprs,juegos,juniper,kaufen,kddi,kerryhotels,kerrylogistics,kerryproperties,kfh,kia,kids,kim,kinder,kindle,kitchen,kiwi,koeln,komatsu,kosher,kpmg,kpn,krd,kred,kuokgroup,kyoto,lacaixa,lamborghini,lamer,lancaster,lancia,land,landrover,lanxess,lasalle,lat,latino,latrobe,law,lawyer,lds,lease,leclerc,lefrak,legal,lego,lexus,lgbt,lidl,life,lifeinsurance,lifestyle,lighting,like,lilly,limited,limo,lincoln,linde,link,lipsy,live,living,loan,loans,locker,locus,loft,lol,london,lotte,lotto,love,lpl,lplfinancial,ltda,lundbeck,luxe,luxury,macys,madrid,maif,maison,makeup,man,management,mango,map,market,marketing,markets,marriott,marshalls,maserati,mattel,mba,mckinsey,med,media,meet,melbourne,meme,memorial,men,menu,merckmsd,miami,microsoft,mini,mint,mit,mitsubishi,mlb,mls,mma,mobi,mobile,moda,moe,moi,mom,monash,money,monster,mormon,mortgage,moscow,moto,motorcycles,mov,movie,msd,mtn,mtr,museum,music,mutual,mutuelle,nab,nadex,nagoya,name,natura,navy,nba,nec,netbank,netflix,network,neustar,new,newholland,news,next,nextdirect,nexus,nfl,ngo,nhk,nico,nike,nikon,nissan,nissay,nokia,northwesternmutual,norton,now,nowruz,nowtv,nra,nrw,ntt,nyc,obi,observer,off,office,okinawa,olayan,olayangroup,oldnavy,ollo,omega,one,onion,online,ono,ooo,open,oracle,orange,organic,origins,osaka,otsuka,ott,ovh,page,panasonic,paris,pars,partners,parts,party,passagens,pay,pcbite,pccw,pet,pfizer,pharmacy,phd,philips,phone,photo,photography,photos,physio,pics,pictet,pictures,pid,pin,ping,pink,pioneer,pizza,place,play,playstation,plumbing,plus,pnc,pohl,poker,politie,porn,post,pramerica,praxi,press,prime,pro,prod,productions,prof,progressive,promo,properties,property,protection,pru,prudential,pub,pwc,qpon,quebec,quest,qvc,racing,radio,raid,read,realestate,realtor,realty,recipes,red,redstone,redumbrella,rehab,reise,reisen,reit,reliance,ren,rent,rentals,repair,report,republican,rest,restaurant,review,reviews,rexroth,rich,richardli,ricoh,rightathome,ril,rio,rip,rmit,rocher,rocks,rodeo,rogers,room,rsvp,rugby,ruhr,run,rwe,ryukyu,saarland,safe,safety,sakura,sale,salon,samsclub,samsung,sandvik,sandvikcoromant,sanofi,sap,sarl,sas,save,saxo,sbi,sbs,sca,scb,schaeffler,schmidt,scholarships,school,schule,schwarz,science,scjohnson,scot,search,seat,secure,security,seek,select,sener,services,ses,seven,sew,sex,sexy,sfr,share,shaw,shell,shia,shiksha,shoes,shop,shopping,shouji,show,showtime,shriram,silk,sina,singles,site,ski,skin,sky,skype,sling,smart,smile,sncf,soccer,social,softbank,software,sohu,solar,solutions,song,sony,soy,spa,space,sport,spot,spreadbetting,srl,srt,stada,staples,star,statebank,statefarm,stc,stcgroup,stockholm,storage,store,stream,studio,study,style,sucks,supplies,supply,support,surf,surgery,suzuki,swatch,swiss,sydney,systems,tab,taipei,talk,taobao,target,tatamotors,tatar,tattoo,tax,taxi,tci,tdk,team,tech,technology,tel,temasek,tennis,teva,thd,theater,theatre,tiaa,tickets,tienda,tiffany,tips,tires,tirol,tjmaxx,tjx,tkmaxx,tmall,today,tokyo,tools,top,toray,toshiba,total,tours,town,toyota,toys,trade,trading,training,travel,travelchannel,travelers,travelersinsurance,trust,trv,tube,tui,tunes,tushu,tvs,ubank,ubs,unicom,university,uno,uol,ups,vacations,vana,vanguard,vegan,vegas,ventures,verisign,versicherung,vet,viajes,video,vig,viking,villas,vin,vip,virgin,visa,vision,viva,vivo,vlaanderen,vodka,volkswagen,volvo,vote,voting,voto,voyage,vuelos,wales,walmart,walter,wang,wanggou,watch,watches,weather,weatherchannel,webcam,weber,website,wed,wedding,weibo,weir,whoswho,wien,wiki,williamhill,win,windows,wine,winners,wme,wolterskluwer,woodside,work,works,world,wow,wtc,wtf,xbox,xerox,xfinity,xihuan,xin,xxx,yahoo,yamaxun,yandex,yodobashi,yoga,yokohama,you,youtube,yun,zappos,zara,zero,zip,zippo,zone,zuerich"

