this._yttv=this._yttv||{};(function(_){var window=this;
try{
_.kEb=new Map([["TEXT",void 0],["BACKSPACE","ytKeyboardKeyBackspace"],["LETTER_LAYOUT","ytKeyboardKeyLayout"],["TOGGLE_LETTER_LAYOUT","ytKeyboardKeyToggleLetterLayout"],["NUMBER_LAYOUT","ytKeyboardKeyLayout"],["SYMBOL_LAYOUT","ytKeyboardKeyLayout"],["SWITCH_LANGUAGE","ytKeyboardKeyLanguageSwitch"],["SHIFT","ytKeyboardKeyShift"],["DISABLED","ytKeyboardKeyDisabled"],["CLEAR","ytKeyboardKeyClear"],["SEARCH","ytKeyboardKeySearch"],["SPACE","ytKeyboardKeySpace"],["MIC","ytKeyboardKeyMic"]]);
}catch(e){_._DumpException(e)}
try{
_.p("LdXxe");

_.r();
}catch(e){_._DumpException(e)}
try{
var lEb=function(a){const b=this.fL;return _.E("host",{dir:"auto","aria-label":a.Ad.ariaLabel,role:"button",className:[b],hybridNavFocusable:!0},_.I(b&&a.Ad.label,()=>_.E("div",{className:"ytKeyboardKeyActionKeyText",idomKey:"label"},a.Ad.label),()=>_.E(_.nm,null,a.Ad.label)))},mEb=function(a){a.j&&a.j.j()&&_.Aj().sounds&&(_.jC(a," "),_.B.get(_.wHa).play(2))},W_=class extends _.U{constructor(){super(...arguments);this.template=lEb;this.onSelect=_.Go;this.cb=_.B.get(_.mC);this.onLongPress=()=>{this.j();
let a,b;(b=(a=this.props).pP)==null||b.call(a,this.props.Ad);_.Ko(13)};this.j=()=>{clearTimeout(this.A);this.A=void 0}}Y(){this.on("pointerleave",this.j);this.on("pointercancel",this.j);this.on("keyup",a=>{a.keyCode===13&&(this.j(),this.jd(a))});this.on("keydown",a=>{a.keyCode===13&&(this.j(),this.A=setTimeout(this.onLongPress,500))})}jd(a){const b=this.props.Ad,c=this.props.jd;b.action==="BACKSPACE"?_.Go(a,!1,!0):_.Lo(a);c(b);this.props.Ns||(this.props.bw?mEb(this.cb):_.jC(this.cb,this.el))}get fL(){return _.kEb.get(this.props.Ad.action)}};
W_.S="yt-keyboard-key";W_.T="ytKeyboardKeyHost";W_.Mb="ytKeyboardKeyFocused";var nEb=_.x("YtKeyboardKey","tPUKgc");var X_=class extends _.U{constructor(){super(...arguments);this.template=lEb;this.cb=_.B.get(_.mC);this.onLongPress=()=>{let a,b;(b=(a=this.props).pP)==null||b.call(a,this.props.Ad)}}onSelect(a){const b=this.props.Ad,c=this.props.jd;b.action==="BACKSPACE"?_.Go(a,!1,!0):_.Lo(a);c(b);this.props.Ns||(this.props.bw?mEb(this.cb):_.jC(this.cb,this.el))}get fL(){return oEb.get(this.props.Ad.action)}},oEb;X_.S="yt-keyboard-key";X_.T="ytKeyboardKeyHost";X_.Mb="ytKeyboardKeyFocused";
oEb=new Map([["TEXT",void 0],["BACKSPACE","ytKeyboardKeyBackspace"],["LETTER_LAYOUT","ytKeyboardKeyLayout"],["TOGGLE_LETTER_LAYOUT","ytKeyboardKeyToggleLetterLayout"],["NUMBER_LAYOUT","ytKeyboardKeyLayout"],["SYMBOL_LAYOUT","ytKeyboardKeyLayout"],["SWITCH_LANGUAGE","ytKeyboardKeyLanguageSwitch"],["SHIFT","ytKeyboardKeyShift"],["DISABLED","ytKeyboardKeyDisabled"],["CLEAR","ytKeyboardKeyClear"],["SEARCH","ytKeyboardKeySearch"],["SPACE","ytKeyboardKeySpace"],["MIC","ytKeyboardKeyMic"]]);
_.Y_=a=>_.A("useLongPressKeyHandler",!1)?_.E(X_,a):_.E(W_,a);_.Vm(_.Y_);_.Q(nEb,_.Y_);
}catch(e){_._DumpException(e)}
try{
_.p("tPUKgc");

_.r();
}catch(e){_._DumpException(e)}
try{
_.jEb=new Map([[228,4],[227,-4],[37,-1],[39,1]]);
}catch(e){_._DumpException(e)}
try{
_.p("rQK23e");

_.r();
}catch(e){_._DumpException(e)}
try{
var pEb,qEb,sEb,tEb,uEb,rEb;
pEb=function(a){let {Bb:b,items:c,Ya:d,focused:e}=a;b=this.wF(b.row,b.col);return _.E("host",{dir:"ltr"},_.E(_.JI,{layout:"vertical",focused:e,selectedIndex:b.row,className:"ytSimpleGridOuterFocusContainer",aa:this.uj,spanName:a.spanName},_.SH(c,(f,g)=>_.E(_.JI,{layout:"horizontal",focused:e&&g===b.row,className:["ytSimpleGridRow",{ytSimpleGridRowFirst:g===0,ytSimpleGridRowLast:g===a.items.length-1}],selectedIndex:b.col,aa:this.Jh,Vb:a.Vb,spanName:a.spanName},_.SH(f,(h,k)=>d({item:h,index:k,selected:e&&
g===b.row&&k===b.col,visibility:"FULLY_VISIBLE",rowIndex:g}))))))};qEb=function(a,b){const c=this.E_(a.oa);return _.E("host",{dir:"ltr",style:this.containerStyle},_.E(_.Z_,{focused:a.focused,items:a.oa,Ya:c,Lc:this.Lc,Bb:b.Bb,Vb:!0}))};sEb=function(a,b,c){const d=c-b>0?1:-1;for(;b!==c&&!rEb(a,b);)b+=d;return b};tEb=function(a,b,c,d){const e=d-c>0?1:-1;for(;!a.hb(b,c)&&c!==d;)c+=e;return c};
uEb=function(a,b,c){const d=a.props.items;let e=b-1;for(;e>=0||b<d.length;){if(a.hb(b,c))return b;if(a.hb(e,c))return e;--e;++b}return-1};rEb=function(a,b){let c,d;return!!((c=a.props.items)==null?0:(d=c[b])==null?0:d.some(e=>{let f,g,h;return(h=(g=(f=a.props).VN)==null?void 0:g.call(f,e))!=null?h:!0}))};
_.Z_=class extends _.U{constructor(){super(...arguments);this.template=pEb;this.Jh=a=>{this.Lc({row:this.props.Bb.row,col:a})};this.uj=a=>{this.Lc({row:a,col:this.props.Bb.col})};this.Lc=({row:a,col:b})=>{const c=this.props.Bb.row,d=this.props.Bb.col;a=this.wF(a,b);c===a.row&&d===a.col||this.props.Lc(a)};this.wF=(a,b)=>{var c=this.props.items,d=this.props.Bb;const e=d.row;d=d.col;if(c.length===0)return{row:e,col:d};var f=_.Bt(0,a,c.length-1);if(this.hb(f,b))return{row:f,col:b};f=sEb(this,f,a-e>0?
c.length-1:0);if(this.hb(f,b))return{row:f,col:b};var g=tEb(this,f,b,b-d>=0?Math.max(c[f].length-1,b):Math.min(b,0));if(this.hb(f,g))return{row:f,col:g};if(a===e)for(c=(a=b-d>=0)?c.reduce((h,k)=>Math.max(h,k.length-1),0)-b:b,g=0;g<=c;g++){const h=b+(a?g:-g),k=uEb(this,f,h);if(k!==-1)return{row:k,col:h}}g=tEb(this,f,b,0);return this.hb(f,g)?{row:f,col:g}:{row:e,col:d}};this.j=a=>{var b=_.jEb.get(_.FI(a.keyCode));if(b!==void 0){var c=this.props.Bb.row,d=this.props.Bb.col;b=this.wF(c,d+b);if(c!==b.row||
d!==b.col)this.props.Lc(b),_.Go(a)}}}Y(){this.on("keydown",this.j)}hb(a,b){const c=this.props.items;let d,e,f,g,h;return a>=0&&a<(c==null?void 0:c.length)&&b>=0&&b<(c==null?void 0:(d=c[a])==null?void 0:d.length)&&((h=(g=(f=this.props).VN)==null?void 0:g.call(f,c==null?void 0:(e=c[a])==null?void 0:e[b]))!=null?h:!0)}};_.Z_.S="yt-simple-grid";_.Z_.T="ytSimpleGridHost";var vEb=_.x("YtKeyboardKeyVariations","rA97qf");var $_;$_=function(a){const b=a.x0;a=a.oa;return a.length&&b?_.Bt(0,b||0,a[a.length-1].length-1):0};
_.a0=class extends _.U{static ob(a,b){return a.focused?b:{Bb:{row:a.oa.length-1,col:$_(a)}}}constructor(a){super(a);this.template=qEb;this.E_=_.M(()=>b=>{const c=this.props.focused;let d;b={Ad:b.item,jd:this.props.jd,focused:b.selected&&c,className:{ytKeyboardKeyVariationsVariationsFirstColItem:b.index===0,ytKeyboardKeyVariationsVariationsShiftedColItem:b.index===$_(this.props),ytKeyboardKeyVariationsVariationsLastColItem:b.index===this.props.oa[(d=b.rowIndex)!=null?d:0].length-1}};return _.E(_.Y_,
b)});this.Lc=b=>{const c=_.Bt(0,b.row,this.props.oa.length-1);this.I({Bb:{row:c,col:_.Bt(0,b.col,this.props.oa[c].length-1)}})};this.state={Bb:{row:a.oa.length-1,col:$_(a)}}}get containerStyle(){var a;const b=(a=this.props.keySize)!=null?a:0;a=$_(this.props);const c=Math.max(...this.props.oa.map(d=>d.length));return{marginLeft:`-${a*b}rem`,width:`${c*b}rem`}}};_.a0.S="yt-keyboard-key-variations";_.a0.T="ytKeyboardKeyVariationsHost";_.Q(vEb,_.a0);
}catch(e){_._DumpException(e)}
try{
_.p("rA97qf");

_.r();
}catch(e){_._DumpException(e)}
try{
var wEb=function(a){const b=a.Ad.zna,c=a.Ad.oa;return _.E("host",{className:["ytKeyboardKeyContainerContainer",{ytKeyboardKeyContainerContainerHasVariations:this.bC}]},_.I(this.bC,()=>_.E(_.a0,{focused:this.Sa("variations"),oa:c,idomKey:"variations",jd:this.Gz,x0:b,keySize:a.keySize})),_.E(_.Y_,{Ad:a.Ad,jd:this.Gz,idomKey:"key",focused:this.Sa("key"),pP:this.rW,Ns:a.Ns,bw:a.bw}))};var xEb=_.x("YtKeyboardKeyContainer","Zv8mYe");_.b0=class extends _.U{static ob(a,b){return a.focused?b:Object.assign({},b,{ka:"key"})}Qb(a,b){if(_.A("enableSearchKeyboardRenderOptimization",!1)){var c=this.props,d=this.state;a=Object.assign({},a,{jd:void 0,selected:void 0});c=Object.assign({},c,{jd:void 0,selected:void 0});b=_.Io(c,a)&&_.Io(d,b)}else b=super.Qb(a,b);return b}constructor(a){super(a);this.template=wEb;this.B=_.B.get(_.TH);this.A=!1;this.j=_.bv((b,c=!0)=>{this.A=!1;this.I({bH:!!b});if((!b||b.oa)&&c){let d,e;(e=(d=this.props).Sp)==
null||e.call(d,b)}},250);this.rW=()=>{this.j(this.props.Ad)};this.Gz=b=>{this.props.jd(b);if(this.bC){this.I({ka:"key"});this.j(null,!1);let c,d;(d=(c=this.props).Sp)==null||d.call(c,null)}};this.Sa=b=>!!this.props.focused&&this.ka===b;this.state={ka:"key",bH:!1}}Y(){this.on("mousemove",()=>{this.state.bH&&!this.A||this.j(this.props.Ad)});this.on("mouseout",()=>{this.A=!0;this.j(null,!1)});this.on("keydown",a=>{this.onKeyDown(a)})}ma(a){if(!a.focused&&this.props.focused&&this.props.Ad.oa){let b,c;
(c=(b=this.props).Sp)==null||c.call(b,this.props.Ad)}}onKeyDown(a){const b=a.keyCode;this.props.Ad.oa&&(b===38&&this.Sa("key")&&this.bC?(_.Lo(a),this.I({ka:"variations"})):b===40&&this.Sa("variations")&&(_.Lo(a),this.I({ka:"key"})))}get ka(){return this.state.ka}get F(){return _.A("enableTouchSupport",!1)&&this.B.Rj===0}get bC(){return(this.props.focused&&!this.F||this.state.bH)&&this.props.Ad===this.props.Yq}get visualElement(){return this.props.Ad.la}};_.b0.S="yt-keyboard-key-container";
_.b0.T="ytKeyboardKeyContainerHost";_.Q(xEb,_.b0);
}catch(e){_._DumpException(e)}
try{
_.p("Zv8mYe");

_.r();
}catch(e){_._DumpException(e)}
try{
var yEb=function(a){return _.E("host",null,_.E(_.Z_,{items:a.keys,Ya:this.F_(a.keys,a.jd,a.focused,a.keySize,a.Ns,a.bw,a.Sp,a.Yq),Lc:a.Lc,Bb:a.Bb,VN:this.RX,focused:a.focused,Vb:!a.flip,spanName:"search-keyboard"}))};var zEb=_.x("YtKeyboardKeyGrid","JiMZI");_.c0=class extends _.U{constructor(){super(...arguments);this.template=yEb;this.F_=_.M((a,b,c,d,e,f,g,h)=>k=>_.E(_.b0,{Ad:k.item,focused:k.selected&&c,jd:m=>{b(m,{row:k.rowIndex,col:k.index})},Ns:e,bw:f,keySize:d,Sp:g,Yq:h}));this.RX=a=>a.action!=="DISABLED"}};_.c0.S="yt-keyboard-key-grid";_.c0.T="ytKeyboardKeyGridHost";_.Q(zEb,_.c0);
}catch(e){_._DumpException(e)}
try{
_.p("JiMZI");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("w5r9zc");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("t7jJHc");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("f9wWK");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("A4F3T");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("H6PyS");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("docyYc");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("q5KBVb");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("Jm4Cvc");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("RYdAfb");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("RWjuEf");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("lPapGd");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("O0JFaf");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("n7qbFe");

_.r();
}catch(e){_._DumpException(e)}
try{
var fEb=function({data:a,focused:b,disableCommand:c,qa:d}){return _.E("host",{id:a.isDisabled?this.props.zb:void 0},_.E(_.CO,{label:a.accountName,role:a.isDisabled?",":void 0,sublabel:a.channelHandle||a.accountByline,command:c||a.isDisabled?void 0:a.serviceEndpoint,avatar:{thumbnail:a.accountPhoto||{},size:"certified_small",style:"circle"},focused:b,qa:d,secondaryIcon:a.isSelected?{iconType:"CHECK"}:void 0}))};_.T_=class extends _.U{constructor(){super(...arguments);this.template=fEb}};_.T_.S="ytlr-account-item-renderer";_.T_.T="ytLrAccountItemRendererHost";_.Q(_.H8a,_.T_);
}catch(e){_._DumpException(e)}
try{
_.p("MgQ01c");

_.r();
}catch(e){_._DumpException(e)}
try{
_.U_=function(a,b){if(!a)return[];const c=[];for(let d=0;d<a;d++)c[d]=void 0;return c.map((d,e)=>b(e))};
}catch(e){_._DumpException(e)}
try{
var hEb=function({data:a,height:b,zb:c}){a=a.expectedPairingNumber;return _.E("host",{className:"ytLrPinPairingRendererHost",style:{height:`${b}rem`},id:c},_.E("div",{"aria-hidden":"true",className:"ytLrPinPairingRendererNumberContainer"},gEb(a?a:"")))},gEb=function(a){return _.U_(a.length,b=>_.E("span",{className:"ytLrPinPairingRendererChar"},a.charAt(b)))};var iEb=_.x("YtlrPinPairingRenderer","e8q6jb");_.V_=class extends _.U{constructor(){super(...arguments);this.template=hEb;this.P=_.Wp.getInstance();this.ba=_.D()}Y(){_.T(this,_.L(this.P,new _.J("mdx-sign-in:status-updated"),this,a=>{switch(a.event){case "canceled":case "exited":const b=[{signalAction:{signal:"POPUP_BACK"}}];a.event!=="canceled"&&b.push(_.wq("CANCELLED","SIGN_IN_METHOD_TYPE_SEAMLESS","ACCOUNT_EVENT_TRIGGER_PASSIVE","TVHTML5_ACCOUNT_EVENT_ERROR_TYPE_PIN_PAIRING_CHALLENGE_CANCELED","TVHTML5_ACCOUNT_EVENT_CANCELLATION_TYPE_USER_CANCELED_ON_MOBILE"));
this.ba.resolveCommand({commandExecutorCommand:{commands:b}})}}))}};_.V_.S="ytlr-pin-pairing-renderer";_.V_.T="ytLrPinPairingRendererHost";_.Q(iEb,_.V_);
}catch(e){_._DumpException(e)}
try{
_.p("e8q6jb");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("lqnTve");


_.r();
}catch(e){_._DumpException(e)}
try{
_.p("IcQfQb");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("m6ewGc");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("hwxEA");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("s96Wjb");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("nFlGSc");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("UMQnke");

_.r();
}catch(e){_._DumpException(e)}
try{
var VSa,WSa,XSa,SSa,USa,TSa;_.VG=function(a){return SSa(_.ha(a.replace(TSa,function(b,c){return USa.test(c)?"":" "}).replace(/[\t\n ]+/g," ")))};VSa=function(a){return a.replace(/&([^;]+);/g,function(b,c){switch(c){case "amp":return"&";case "lt":return"<";case "gt":return">";case "quot":return'"';default:return c.charAt(0)!="#"||(c=Number("0"+c.slice(1)),isNaN(c))?b:String.fromCharCode(c)}})};WSa=/&([^;\s<&]+);?/g;
XSa=function(a){const b={"&amp;":"&","&lt;":"<","&gt;":">","&quot;":'"'};let c;c=_.fb.document.createElement("div");return a.replace(WSa,function(d,e){let f=b[d];if(f)return f;e.charAt(0)=="#"&&(e=Number("0"+e.slice(1)),isNaN(e)||(f=String.fromCharCode(e)));f||(_.Oa(c,_.Ea(d+" ")),f=c.firstChild.nodeValue.slice(0,-1));return b[d]=f})};SSa=function(a){return _.fa(a,"&")?"document"in _.fb?XSa(a):VSa(a):a};USa=/^(?:abbr|acronym|address|b|em|i|small|strong|su[bp]|u)$/i;TSa=/<[!\/]?([a-z0-9]+)([\/ ][^>]*)?>/gi;
}catch(e){_._DumpException(e)}
try{
_.YSa=new _.O("mediaProductRenderer");
}catch(e){_._DumpException(e)}
try{
_.WG=function(a,b,c){return{entityUpdateCommand:{entityBatchUpdate:{mutations:[Object.assign({},{entityKey:a,type:"ENTITY_MUTATION_TYPE_UPDATE",payload:b},c?{fieldMask:c}:{})]}}}};
}catch(e){_._DumpException(e)}
try{
var $Sa,aTa;_.XG=function(a,b,c,d){b={flowStateEntity:Object.assign({},{key:a,currentStepId:b},c?{stepIdStack:d?d:[b]}:{})};return _.WG(a,b,c?{mergeOptions:{repeatedFieldsMergeOption:c}}:void 0)};$Sa=function(a){const b={signalAction:{signal:"POPUP_BACK"}};return _.Wn({uniqueId:"offers-payment-selector",overlayPanelRenderer:_.u(a,_.uA)||{},dismissalCommand:b,backButton:{command:b}})};
aTa=function(){var a=_.H("PURCHASE_TOS_SELECTOR_OVERLAY_TITLE"),b=_.H("PURCHASE_TOS_SELECTOR_OVERLAY_SUBTITLE");a=_.co({title:a,subtitle:b});b={compactLinkRenderer:{title:{simpleText:_.H("PURCHASE_TOS_ITEM_PAID_SERVICE")},secondaryIcon:{iconType:"CHEVRON_RIGHT"},navigationEndpoint:{signalAction:{signal:"OPEN_PAID_SERVICE_TERMS"}}}};const c={compactLinkRenderer:{title:{simpleText:_.H("PURCHASE_TOS_ITEM_TERMS")},secondaryIcon:{iconType:"CHEVRON_RIGHT"},navigationEndpoint:{signalAction:{signal:"OPEN_TERMS_OF_SERVICE"}}}},
d={compactLinkRenderer:{title:{simpleText:_.H("PURCHASE_TOS_ITEM_PAY_CONTENT")},secondaryIcon:{iconType:"CHEVRON_RIGHT"},navigationEndpoint:{signalAction:{signal:"OPEN_PAID_CONTENT_TERMS"}}}},e={overlayMessageRenderer:_.bo({title:_.H("PURCHASE_TOS_LEGAL_TEXT"),style:"OVERLAY_MESSAGE_STYLE_DISCLAIMER"})};a=_.eo(a,[b,c,d,e]);b={signalAction:{signal:"POPUP_BACK"}};return _.Wn({overlayPanelRenderer:a,dismissalCommand:b,backButton:{command:b}})};
_.YG=function(a,b,c){var d,e,f=(e=a==null?void 0:(d=a.lineItemBundle)==null?void 0:d[0])==null?void 0:e.heroItem,g;d={thumbnails:[{url:f==null?void 0:(g=f.image)==null?void 0:g.imageUri}]};g=_.Tn((f==null?void 0:f.name)||"");const h=[];((f==null?void 0:f.infoMessage)||[]).forEach(k=>{(k.messageHtml||"").split("<br>").forEach(m=>{m={metadataLineRenderer:{text:_.Tn(_.VG(m)||"")}};h.push(m)})});b=b?b.map(k=>(k.messageHtml||"").split("<br>").map(m=>_.VG(m)).join("\n")):[];b=_.Tn(b.join("\n"));f=[];_.A("enablePaidTosViewer",
!1)&&(e={buttonRenderer:{size:"SIZE_DEFAULT",text:{simpleText:_.H("PURCHASE_TOS_SELECTOR_OVERLAY_TITLE")},navigationEndpoint:aTa(),style:"STYLE_DEFAULT",icon:{iconType:"PRIVACY_INFO"}}},f.push(e));if(e=c==null?void 0:c.contactInfoRenderer)e={buttonRenderer:{size:"SIZE_DEFAULT",text:{simpleText:_.H("CONTACT_SUPPORT")},style:"STYLE_DEFAULT",navigationEndpoint:$Sa(e)}},f.push(e);return{offerDetailRenderer:{product:{mediaProductRenderer:{thumbnail:d,thumbnailStyle:c==null?void 0:c.mediaProductThumbnailStyle,
title:g,metadataLines:h}},checkoutPricingDetail:{lineItemContainer:a},linkOutButtons:f,terms:b}}};_.ZG=function(a,b,c){return{updateFlowCommand:{targetId:a,steps:b,entityUpdateCommand:c}}};_.$G=function(a,b,c){return{flowStepRenderer:Object.assign({},{stepId:a,content:b},c?{onStepBackCommand:c}:{})}};_.aH=function(a,b){return{twoColumnStepRenderer:Object.assign({},{leftColumn:a},b&&{rightColumn:b})}};
_.bH=function(a,b,c){return{actionSectionRenderer:Object.assign({},{actionList:a},b&&{description:_.Tn(b)},c?{displayId:c}:{})}};_.cH=function(a,b,c,d,e){return{actionSelectionRenderer:Object.assign({},{title:_.Tn(a)},c?{masthead:c}:{},{body:[b]},d?{activeSectionDisplayId:d}:{},e?{activeButtonDisplayId:e}:{})}};
_.dH=function(a,b,c){var d=[],e=c==null?void 0:c.retryCommand;e&&d.push({compactLinkRenderer:{serviceEndpoint:e,icon:{iconType:"ARROW_CIRCLE"},title:{simpleText:_.H("TRY_AGAIN")},style:"COMPACT_LINK_STYLE_TYPE_TVFILM_ENTITY_PROVIDER"}});(e=c==null?void 0:c.selectAnotherPaymentMethodCommand)&&d.push({compactLinkRenderer:{serviceEndpoint:e,icon:{iconType:"CREDIT_CARD"},title:{simpleText:_.H("SELECT_ANOTHER_PAYMENT_METHOD_TEXT")},style:"COMPACT_LINK_STYLE_TYPE_TVFILM_ENTITY_PROVIDER"}});(e=c==null?void 0:
c.secondScreenCommand)&&d.push({compactLinkRenderer:{serviceEndpoint:e,icon:{iconType:"PHONELINK"},title:{simpleText:_.H("BUY_ON_ANOTHER_DEVICE_TEXT")},style:"COMPACT_LINK_STYLE_TYPE_TVFILM_ENTITY_PROVIDER"}});d.push({compactLinkRenderer:{title:{simpleText:_.H("CANCEL_PURCHASE_TEXT")},icon:{iconType:"DISMISSAL"},serviceEndpoint:{signalAction:{signal:"FLOW_ENDED"}},style:"COMPACT_LINK_STYLE_TYPE_TVFILM_ENTITY_PROVIDER"}});e=(c==null?void 0:c.title)||_.H("SOMETHING_WENT_WRONG");const f=(c==null?void 0:
c.subtitle)||_.H("PLEASE_TRY_AGAIN");d=_.cH(e,_.bH(d,f));c=(c==null?void 0:c.offerDetailRenderer)||((c==null?0:c.lineItemContainer)?_.YG(c.lineItemContainer,c==null?void 0:c.infoMessage,c==null?void 0:c.googlePaymentPayload):void 0);c=_.aH(d,c);c=_.$G("error_step",c);d=[];d.push(c);return _.ZG(a,d,_.XG(b,"error_step","REPEATED_FIELDS_MERGE_OPTION_REPLACE",["error_step"]))};_.bTa=new _.O("flowStepRenderer");_.eH=new _.O("actionSectionRenderer");_.cTa=new _.O("offerDetailRenderer");
}catch(e){_._DumpException(e)}
try{
var DEb=function(a,b){const c=this.props.rK,d=c?AEb.get("NUMBER_LAYOUT"):BEb.get("NUMBER_LAYOUT"),e=b.Ap?"CHECK_BOX":"CHECK_BOX_OUTLINE_BLANK",f=c?2:3;return _.E("host",{"aria-labelledby":`${this.tb.uB.toString()}`,role:",",className:{ytLrPaymentChallengeKeyboardRendererRtl:_.A("isRtl",!1),ytLrPaymentChallengeKeyboardRendererRegularHeight:!c}},_.I(a.data.description,g=>_.E(_.V,{id:this.tb.uB,className:"ytLrPaymentChallengeKeyboardRendererDescription",data:{simpleText:g}})),_.E("div",{className:["ytLrPaymentChallengeKeyboardRendererInput",
{ytLrPaymentChallengeKeyboardRendererInputFlows:c}]},_.U_(this.maxLength||0,g=>_.E("span",{className:["ytLrPaymentChallengeKeyboardRendererChar",{ytLrPaymentChallengeKeyboardRendererCharFlows:c}]},b.input.charAt(g)?"*":""))),_.E(_.c0,{className:["ytLrPaymentChallengeKeyboardRendererChallengeKeyboard","ytLrPaymentChallengeKeyboardRendererChallengeKeyboardYoutubeStandardsIcon",{ytLrPaymentChallengeKeyboardRendererChallengeKeyboardFlow:c}],focusId:"keyboard",onDownFocus:this.qw?"opt_out":"submit",focused:this.isFocused("keyboard"),
keys:d.keys,jd:this.jd,Bb:b.Lw,Lc:this.ZI,flip:c}),_.I(this.qw,g=>_.E(_.CO,{focusId:"opt_out",onUpFocus:"keyboard",onDownFocus:"submit",className:["ytLrPaymentChallengeKeyboardRendererReauthOptOutCheckbox",{ytLrPaymentChallengeKeyboardRendererReauthOptOutCheckboxUnifiedMargin:!c}],idomKey:"ytLrPaymentChallengeKeyboardRendererReauthOptOutCheckbox",label:g,secondaryIcon:{iconType:e},focused:this.isFocused("opt_out"),gp:this.IZ,qa:24,Eh:!0,CC:!0})),_.I(c,()=>_.E(_.UO,{focusId:"submit",onUpFocus:this.qw?
"opt_out":"keyboard",focused:this.isFocused("submit"),className:"ytLrPaymentChallengeKeyboardRendererSubmitFlows",qa:24,data:{style:"COMPACT_LINK_STYLE_TYPE_TVFILM_ENTITY_PROVIDER",title:{runs:[{text:_.H("PURCHASES_PAY_NOW_BUTTON_TEXT")}]},navigationEndpoint:CEb.command},Ja:!0}),()=>_.E(_.PJ,{focusId:"submit",onUpFocus:this.qw?"opt_out":"keyboard",focused:this.isFocused("submit"),className:"ytLrPaymentChallengeKeyboardRendererSubmit",data:CEb,shape:f,Ja:!1})),_.I(a.data.legalMessage,g=>_.E(_.YM,{data:_.bo({title:g,
style:"OVERLAY_MESSAGE_STYLE_DISCLAIMER"})})))};var EEb=_.x("YtlrPaymentChallengeKeyboardRenderer","Z6yDae");var FEb={keys:[[{label:"1",action:"TEXT"},{label:"2",action:"TEXT"},{label:"3",action:"TEXT"},{label:"4",action:"TEXT"},{label:"5",action:"TEXT"},{label:"",action:"DISABLED"}],[{label:"6",action:"TEXT"},{label:"7",action:"TEXT"},{label:"8",action:"TEXT"},{label:"9",action:"TEXT"},{label:"0",action:"TEXT"},{label:"",action:"BACKSPACE",ariaLabel:_.H("KEYBOARD_DELETE")}]]},BEb=new Map([["NUMBER_LAYOUT",FEb]]),GEb={keys:[[{label:"1",action:"TEXT"},{label:"2",action:"TEXT"},{label:"3",action:"TEXT"},{label:"4",
action:"TEXT"},{label:"5",action:"TEXT"}],[{label:"6",action:"TEXT"},{label:"7",action:"TEXT"},{label:"8",action:"TEXT"},{label:"9",action:"TEXT"},{label:"0",action:"TEXT"},{label:"",action:"BACKSPACE",ariaLabel:_.H("KEYBOARD_DELETE")}]]},AEb=new Map([["NUMBER_LAYOUT",GEb]]);var CEb={command:{signalAction:{signal:"SEND_PAYMENT"}},isDisabled:!1,text:{runs:[{text:_.H("PURCHASES_PAY_NOW_BUTTON_TEXT")}]}};var HEb;
HEb=function(a){try{a.instrumentOption=JSON.parse(a.props.data.instrumentOptionSerialized||"")}catch(m){_.z(Error("Wg`"+m))}var b,c,d;const e=(b=a.instrumentOption)==null?void 0:(c=b.fixInfoForm)==null?void 0:(d=c.instrumentForm)==null?void 0:d.simpleForm;let f;a.B=e==null?void 0:(f=e.formHeader)==null?void 0:f.uiReference;let g;a.A=e==null?void 0:(g=e.formHeader)==null?void 0:g.dataToken;let h;a.formId=e==null?void 0:(h=e.formHeader)==null?void 0:h.id;let k;for(const m of((k=e)==null?void 0:k.formField)||
[]){let n;if(b=(n=m.field)==null?void 0:n.uiField)(c=b.name,d=b.textField,c!=="cvc"&&c!=="lguplusPin"||!d)?c==="optOutReauthField"&&b.checkbox&&(a.Ap=b.checkbox.initialValue===1,a.qw=_.VG(b.checkbox.labelHtml||""),a.j=c):(a.G=c,d.maxLength&&(a.maxLength=d.maxLength),d.minLength&&(a.minLength=d.minLength),a.dataToken=b.dataToken,a.uiReference=b.uiReference,a.isSecure=!!b.isSecure)}};
_.d0=class extends _.U{constructor(a){super(a);this.template=DEb;this.P=_.Wp.getInstance();this.ba=_.D();this.tb={uB:_.ln("ytlr-payment-challenge-keyboard-renderer")};this.isSecure=!1;this.minLength=3;this.Ap=!1;this.j="";this.maxLength=4;this.qw="";this.F=()=>{if(this.state.input.length>=this.minLength&&this.state.input.length<=this.maxLength){var b=this.ba,c=b.resolveCommand,d=this.props.data.isNativeV2Flow,e=JSON,f=e.stringify,g={name:this.G,uiReference:this.uiReference,dataToken:this.dataToken};
let h=this.state.input;this.isSecure&&(h="__secure_field__4fa1d0a7"+h,g.eesSessionMaterial="__s7e_data__61bb463a");g.stringValue=h;g=[{fieldValue:{uiFieldValue:g}}];this.j&&g.push({fieldValue:{uiFieldValue:{name:"optOutReauthField",checkboxState:this.state.Ap?1:2}}});c.call(b,{submitPurchaseCommand:{isNativeV2Flow:d,fixInfoFormValue:f.call(e,{instrumentFormValue:{simpleForm:{id:this.formId,dataToken:this.A,formFieldValue:g,uiReference:this.B}}}),selectedPaymentIndex:this.props.data.selectedPaymentIndex}})}else this.props.data.isNativeV2Flow&&
this.props.data.targetId&&this.props.data.entityKey?(b=this.props.data.offerDetailRenderer,c=this.props.data.retryCommand,d=this.props.data.secondScreenCommand,b=_.dH(this.props.data.targetId,this.props.data.entityKey,{title:_.H("PURCHASES_INVALID_CVC"),subtitle:"",offerDetailRenderer:b,retryCommand:c,secondScreenCommand:d}),this.ba.resolveCommand(b)):(b=this.ba,c=b.resolveCommand,d=this.props.data.contextualPanelRenderer,e=_.H("PURCHASES_INVALID_CVC"),e=_.co({title:e}),f=[{compactLinkRenderer:{title:{simpleText:_.H("TRY_AGAIN")},
serviceEndpoint:{signalAction:{signal:"POPUP_BACK"}}}},{compactLinkRenderer:{navigationEndpoint:_.gH(),title:{simpleText:_.H("PURCHASE_SECOND_DEVICE_OPTION_TEXT")}}},{compactLinkRenderer:{title:{simpleText:_.H("CANCEL_BUTTON_TEXT")},serviceEndpoint:{signalAction:{signal:"CLOSE_POPUP"}}}}],e=_.eo(e,f),d=_.Wn({uniqueId:"offers-unique-id",overlayPanelRenderer:e,contextualPanelRenderer:d}),c.call(b,d)),this.I({input:""})};this.jd=b=>{const c=b.label;switch(b.action){case "TEXT":this.state.input.length!==
this.maxLength&&this.I({input:this.state.input+c});break;case "BACKSPACE":this.I({input:this.state.input.slice(0,-1)})}};this.IZ=()=>{this.I({Ap:!this.state.Ap})};this.ZI=b=>{this.I({Lw:b})};this.isFocused=b=>!!this.props.focused&&this.state.ka===b;HEb(this);this.state={input:"",Ap:this.Ap,Lw:{row:0,col:0},ka:"keyboard"}}Y(){_.T(this,_.L(this.P,new _.J("SEND_PAYMENT"),this,this.F))}get ka(){return this.state.ka}sb(a){this.I({ka:a})}};_.d0.S="ytlr-payment-challenge-keyboard-renderer";_.d0.T="ytLrPaymentChallengeKeyboardRendererHost";
_.Q(EEb,_.d0);
}catch(e){_._DumpException(e)}
try{
_.p("Z6yDae");

_.r();
}catch(e){_._DumpException(e)}
try{
var cEb;cEb=function({data:a,focused:b,qa:c}){var d;let e,f;const g=(f=(d=a.thumbnailRenderer)==null?void 0:(e=d.playlistVideoThumbnailRenderer)==null?void 0:e.thumbnail)!=null?f:{};d=this.isSelected()?"CHECK_BOX":"CHECK_BOX_OUTLINE_BLANK";return _.E("host",null,_.E(_.CO,{label:a.title,thumbnail:g,secondaryIcon:{iconType:d},focused:b,qa:c,gp:this.onSelect}))};_.dEb=new _.O("playlistAddToOptionRenderer");var eEb=_.x("YtlrPlaylistAddToOptionRenderer","b9vpke");_.S_=class extends _.U{constructor(){super(...arguments);this.template=cEb;this.onSelect=a=>{const b=this.isSelected(),c=b?this.props.data.removeFromPlaylistServiceEndpoint:this.props.data.addToPlaylistServiceEndpoint;c&&this.Ob("innertube-command",c);this.props.data.containsSelectedVideos=b?"NONE":"ALL";this.ya();a&&_.Lo(a)}}isSelected(){return this.props.data.containsSelectedVideos==="ALL"}};_.S_.S="ytlr-playlist-add-to-option-renderer";_.S_.T="ytLrPlaylistAddToOptionRendererHost";_.Q(eEb,_.S_);
}catch(e){_._DumpException(e)}
try{
_.p("b9vpke");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("wIZ3tb");

_.r();
}catch(e){_._DumpException(e)}
try{
var IEb=function(a){if(!a.data)return _.E("host",null);const b=a.data.heading,c=a.data.logo,d=a.data.qrCodeImage,e=a.data.title,f=a.data.url,g={};a.zb&&(g.id=a.zb);return _.E("host",Object.assign({},g),_.E("div",{className:["ytLrSecondScreenActionBrand",{ytLrSecondScreenActionHidden:!c||!e}]},_.I(c,h=>_.E("div",{idomKey:"logo",className:"ytLrSecondScreenActionBrandLogo"},_.E(_.gJ,{data:h,width:3,className:"ytLrSecondScreenActionBrandLogoThumbnail"}))),_.I(e,h=>_.E("div",{idomKey:"title",className:"ytLrSecondScreenActionTitle"},
_.E(_.V,{data:h,className:"ytLrSecondScreenActionTitleText"})))),_.E("div",{className:"ytLrSecondScreenActionHeading"},_.E(_.V,{data:b,className:"ytLrSecondScreenActionHeadingText"})),_.E("div",{className:"ytLrSecondScreenActionInstruction"},_.H("VISIT_LINK")),_.E("div",{className:"ytLrSecondScreenActionUrl"},_.E(_.V,{data:f,className:"ytLrSecondScreenActionUrlText"})),_.I(d,h=>_.E(_.nm,null,_.E("div",{className:"ytLrSecondScreenActionInstruction"},_.H("SCAN_QR")),_.E("div",{className:"ytLrSecondScreenActionQrCode"},
_.E(_.gJ,{data:h,width:20,className:"ytLrSecondScreenActionQrCodeThumbnail"})))))};var JEb=_.x("YtlrSecondScreenAction","fMVwCd");_.e0=class extends _.U{constructor(){super(...arguments);this.template=IEb}};_.e0.S="ytlr-second-screen-action";_.e0.T="ytLrSecondScreenActionHost";_.Q(JEb,_.e0);
}catch(e){_._DumpException(e)}
try{
_.p("fMVwCd");

_.r();
}catch(e){_._DumpException(e)}
try{
_.p("o8Fj5c");

_.r();
}catch(e){_._DumpException(e)}
try{
var gvb=function(a){if(!a)return{};let b;return(a=a==null?void 0:(b=a.image)==null?void 0:b.sources)?{thumbnails:a.map(c=>({url:c.url,width:c.width,height:c.height})),accessibility:{accessibility:"avatar.accessibilityText"}}:{}},hvb=function({data:{notificationsLabel:a,currentStateId:b,states:c,command:d,secondaryIcon:e,avatar:f},focused:g,te:h,qa:k,subscribed:m,subscribeCommand:n,SJ:q,Ja:v},{selectedIndex:w}){const y=this.tV(),C=k!=null?k:_.F("25.5rem"),G={width:`${C}rem`},K=_.A("useModernOverlayListItemStyle",
!1)&&!_.A("isLimitedMemory",!1),P=n&&q,W=()=>{var Y={iconType:"NOTIFICATIONS_NONE"};if(P&&!m)return Y;Y={iconType:"NOTIFICATIONS_OFF"};const aa=!(c==null?0:c.length);let ja;const pa=y==null?void 0:(ja=y.state)==null?void 0:ja.buttonRenderer;return!aa&&(pa==null?0:pa.icon)?pa.icon:Y};k=Y=>{const {bK:aa,ariaLabel:ja}=this.xu(y,m,n,q,a),pa=f?gvb(_.u(f,_.$I)):void 0,xa=!f&&m?W():void 0;let Ga=Y?1:_.wo?6:5;Y&&m&&(Ga=_.wo?6:5);return _.A("paprikaButtonPhase1",!1)?Y&&!m?_.E("host",null,_.E(_.XI,{ariaLabel:ja,
command:n,focused:g,Mr:pa,leadingIcon:xa,size:"small",title:aa,Ja:v})):_.E("host",null,_.E(_.YI,{ariaLabel:ja,avatar:pa,command:m?d:n,focused:g,icon:Y?xa:W(),Kc:_.ODa&&(xa==null?void 0:xa.iconType)==="NOTIFICATIONS_NONE",size:"small",title:aa,cn:_.wo?"below":"above",Ja:v})):_.E("host",null,_.E(_.jJ,{ariaLabel:ja,command:m?d:n,focused:g,Kc:_.ODa&&(xa==null?void 0:xa.iconType)==="NOTIFICATIONS_NONE",label:aa,primaryIcon:Y?xa:W(),shape:Ga,thumbnail:pa,title:aa,Ja:v}))};const N=()=>{const {bK:Y,ariaLabel:aa}=
this.xu(y,m,n,q,a),ja=m?W():void 0;return _.A("paprikaButtonPhase1",!1)?m?_.E("host",null,_.E(_.YI,{ariaLive:"polite",ariaLabel:aa,command:d,focused:g,icon:ja,size:"small"})):_.E("host",null,_.E(_.XI,{ariaLive:"polite",ariaLabel:aa,command:n,focused:g,size:"small",title:Y})):_.E("host",null,_.E(_.jJ,{ariaLive:"assertive",ariaLabel:aa,command:m?d:n,focused:g,primaryIcon:ja,shape:m?_.wo?6:5:1,title:Y,Ja:v}))},S=()=>_.E("host",{style:G,className:"ytLrSubscriptionNotificationToggleButtonRendererInlineButtonContainer"},
_.E(_.iK,{Sh:!1,currentIndex:w!=null?w:0,items:c!=null?c:[],active:g}),_.E(_.JI,{layout:"vertical",aa:this.aa,selectedIndex:w!=null?w:0,focused:g},_.SH(c,(Y,aa)=>{const ja=_.u(Y==null?void 0:Y.inlineMenuButton,_.iA);var pa;let xa;const Ga=Y==null?void 0:(pa=Y.state)==null?void 0:(xa=pa.buttonRenderer)==null?void 0:xa.icon;pa=b===(Y==null?void 0:Y.stateId)?{iconType:"CHECK"}:void 0;let Ca,Ma,yb,ob,vc,Vb,nc;return _.E(_.CO,{className:["ytLrSubscriptionNotificationToggleButtonRendererMenuItem","ytLrSubscriptionNotificationToggleButtonRendererMenuItemBgColor",
{ytLrSubscriptionNotificationToggleButtonRendererMenuItemLastChild:aa===((vc=c==null?void 0:c.length)!=null?vc:0)-1,ytLrSubscriptionNotificationToggleButtonRendererMenuItemBgColorUseTransparentBackground:K}],label:(Vb=ja==null?void 0:ja.text)!=null?Vb:Y==null?void 0:(Ca=Y.state)==null?void 0:(Ma=Ca.buttonRenderer)==null?void 0:Ma.text,icon:Ga,secondaryIcon:pa,command:(nc=ja==null?void 0:ja.serviceEndpoint)!=null?nc:Y==null?void 0:(yb=Y.state)==null?void 0:(ob=yb.buttonRenderer)==null?void 0:ob.command,
gp:this.m_,role:"checkbox",qa:C})})));return h===1?S():h===2?_.E("host",null,_.E(_.qI,{fontSize:1.25,icon:W()})):h===3?k(!1):h===4?k(!0):h===5?N():(()=>{const {bK:Y,ariaLabel:aa}=this.xu(y,m,n,q,a);var ja=!!e;const pa=ja?e:W();ja=ja?W():void 0;return _.E("host",{style:G,className:"ytLrSubscriptionNotificationToggleButtonRendererInlineButtonContainer"},_.E(_.CO,{ariaLabel:aa,className:["ytLrSubscriptionNotificationToggleButtonRendererMenuItem","ytLrSubscriptionNotificationToggleButtonRendererMenuItemLastChild"],
focused:g,label:Y,icon:ja,secondaryIcon:P&&!m?void 0:pa,command:P&&!m?n:d,qa:C}))})()},ivb=_.x("YtlrSubscriptionNotificationToggleButtonRenderer","OMuq7e");var WW=class extends _.U{constructor(a){super(a);this.template=hvb;this.ba=_.D();this.xu=_.M((c,d,e,f,g)=>{e=e&&f&&!d?f:g;var h;let k,m;c=d&&(c==null?void 0:(h=c.state)==null?void 0:(k=h.buttonRenderer)==null?void 0:(m=k.accessibility)==null?void 0:m.label)||"";h=_.WM([e,c]).slice(0,-2);return{bK:e,ariaLabel:h}});this.j=({stateId:c})=>{let d;return c===((d=this.props.data)==null?void 0:d.currentStateId)};this.A=()=>{let c,d;return(d=(c=this.props.data.states)==null?void 0:c.findIndex(this.j))!=null?
d:0};this.tV=()=>{let c;return(c=this.props.data.states)==null?void 0:c.find(this.j)};this.aa=c=>{this.I({selectedIndex:c})};this.m_=()=>{this.ba.resolveCommand({signalAction:{signal:"POPUP_BACK"}})};let b=0;a.te===1&&(b=Math.max(this.A(),0));this.state={selectedIndex:b}}};WW.S="ytlr-subscription-notification-toggle-button-renderer";WW.T="ytLrSubscriptionNotificationToggleButtonRendererHost";
_.XW=_.uI(WW,function({entities:a}){return a.subscriptionNotificationStateEntity},function(a,{data:b}){const c=b.notificationStateEntityKey;if(!c)return{};let d;const e=(d=_.bj(a.entities,"subscriptionNotificationStateEntity",c))==null?void 0:d.state;if(!e)return{};let f,g,h;a=(h=(f=b.states)==null?void 0:(g=f.find(k=>(k==null?void 0:k.notificationState)===e))==null?void 0:g.stateId)!=null?h:0;return{data:Object.assign({},b,{currentStateId:a})}});_.Q(ivb,_.XW);
}catch(e){_._DumpException(e)}
try{
_.p("OMuq7e");

_.r();
}catch(e){_._DumpException(e)}
try{
var jvb=function(a){let b,c,d;return(d=(b=a.onSubscribeEndpoints)==null?void 0:b[0])!=null?d:(c=a.serviceEndpoints)==null?void 0:c[0]},kvb=function({data:a,focused:b,te:c=1,qa:d,Ja:e,XO:f}){const g=a.subscribed,h=a.subscribedButtonText,k=a.unsubscribedButtonText;var m=a.notificationPreferenceButton;const n=a.subscribeStateIcons,q=a.icon,v=this.iW(),w=m==null?void 0:m.subscriptionNotificationToggleButtonRenderer;m=K=>_.E("host",null,_.I(w,P=>_.E(_.XW,{data:P,focused:b,subscribeCommand:this.jm(),SJ:v,
subscribed:g,te:K?4:3,Ja:e,idomKey:"Notifications"})));const y=()=>_.E("host",null,_.I(w,K=>_.E(_.XW,{data:K,focused:b,subscribeCommand:this.jm(),SJ:v,subscribed:g,te:5,Ja:e,idomKey:"notification-compact-bell"}))),C=()=>_.E("host",null,_.E(_.V,{className:"ytLrSubscribeButtonRendererCompactModeText",data:g?h:k}),_.I(g&&w,K=>_.E(_.XW,{className:"ytLrSubscribeButtonRendererNotificationToggle",data:K,te:2,idomKey:"notification-icon",qa:d}))),G=()=>{const K=d!=null?d:_.F("25.5rem"),P=!(!a.subscribedButtonText||
!_.AN(a)),W={width:`${K}rem`},N=_.A("useModernOverlayListItemStyle",!1)&&!_.A("isLimitedMemory",!1);let S;return _.E("host",{style:W,className:"ytLrSubscribeButtonRendererInlineButtonContainer"},_.E(_.iK,{Sh:!1,row:f!=null?f:0,column:(S=this.state.selectedIndex)!=null?S:0,active:f!==void 0&&b&&!!w}),_.E(_.JI,{layout:"vertical",aa:this.aa,selectedIndex:this.state.selectedIndex,focused:b},_.I(P,()=>_.E(_.CO,{className:["ytLrSubscribeButtonRendererInlineModeMenuItem","ytLrSubscribeButtonRendererMenuItem",
{ytLrSubscribeButtonRendererMenuItemLastChild:!(g&&w),ytLrSubscribeButtonRendererMenuItemUseTransparentBackground:N}],label:g?h:v,icon:q,idomKey:"Subscribe",command:this.jm(),qa:K})),_.I((g||!P)&&w,Y=>_.E(_.XW,{className:["ytLrSubscribeButtonRendererMenuItem","ytLrSubscribeButtonRendererMenuItemLastChild",{ytLrSubscribeButtonRendererMenuItemUseTransparentBackground:N}],data:Y,subscribeCommand:P?void 0:this.jm(),SJ:P?void 0:v,subscribed:g,te:0,idomKey:"Notifications",qa:K}))))};return c===0?G():c===
4?C():c===5?m(!1):c===6?m(!0):c===7&&w?y():_.E("host",null,_.E(_.UK,{className:"ytLrSubscribeButtonRendererButtonModeToggleRenderer",data:{defaultCommand:jvb(a),defaultIcon:n==null?void 0:n.unsubscribedIcon,defaultText:v,isToggled:g,toggledCommand:_.AN(a),toggledIcon:n==null?void 0:n.subscribedIcon,toggledText:h},preventAutoToggle:!0,focused:b,shape:c===3?_.wo?6:5:c===2?9:1,Ja:e,qa:d}))};var YW=class extends _.U{constructor(){super(...arguments);this.template=kvb;this.cb=_.B.get(_.mC);this.state={selectedIndex:0};this.aa=a=>{this.I({selectedIndex:a})};this.jm=()=>{const a=this.props.data;return a.subscribed?_.AN(a):jvb(a)};this.iW=()=>{const a=this.props.data.unsubscribedButtonText,b=this.props.data.subscriberCountText;let c;return this.j((c=this.props.Bla)!=null?c:!1,a,b)};this.j=_.M((a,b,c)=>a?{simpleText:`${_.Rn(b)} ${_.Rn(c)}`}:b)}static ob(a,b){return a.data.subscribed||b.selectedIndex!==
1?b:Object.assign({},b,{selectedIndex:0})}ma(a){if(a.data.subscribed!==this.props.data.subscribed){var b;((b=this.props.data.notificationPreferenceButton)==null?0:b.subscriptionNotificationToggleButtonRenderer)&&_.Bk().then(()=>{this.Ob("listItemResizeAction")});this.props.focused&&_.iC(this.cb,this.el)}}};YW.S="ytlr-subscribe-button-renderer";YW.T="ytLrSubscribeButtonRendererHost";
_.ZW=_.uI(YW,function({entities:a}){return a.subscriptionStateEntity},function(a,{data:b}){const c=b.subscribedEntityKey;if(!c)return{};let d,e;a=(e=(d=_.bj(a.entities,"subscriptionStateEntity",c))==null?void 0:d.subscribed)!=null?e:b.subscribed;return b.subscribed===a?{}:{data:Object.assign({},b,{subscribed:a})}});_.Q(_.G0a,_.ZW);
}catch(e){_._DumpException(e)}
try{
_.p("KR76jc");

_.r();
}catch(e){_._DumpException(e)}
try{
_.RAb=new _.O("counterfactualRenderer");
}catch(e){_._DumpException(e)}
try{
_.fH=function(a){let b=0;for(let c=0;c<a.length;++c)b=31*b+a.charCodeAt(c)>>>0;return b};_.dTa=new _.O("paymentChallengeKeyboardRenderer");
}catch(e){_._DumpException(e)}
try{
_.OY=class extends _.U{constructor(a){super(a);this.za=_.B.get(_.qn);this.j=new Set(this.props.items);this.state={WF:!1,isReady:!1,version:0};this.getSize=c=>{let d;return(d=this.Tg.get(c))!=null?d:0};this.A=_.bv(()=>{this.j.size||_.Bk().then(()=>{this.I({WF:!0,isReady:!0,version:this.state.version+1})})},0,this);this.B=c=>d=>{d/=_.Gq(this.za);this.Tg.set(c,Math.ceil(d/.125)*.125);this.j.delete(c);this.A()};this.F=()=>this.j.size?_.E("div",{idomKey:"pending",style:{visibility:"hidden"}},_.SH([...this.j],
(c,d)=>_.E(pzb,{onMount:this.B(c),layout:this.props.layout},this.props.Ya({item:c,index:d,selected:!1,visibility:"OFFSCREEN"})))):null;this.template=()=>{const c=this.state.isReady;return _.E("host",{"aria-hidden":!c},_.I(c,()=>{let d;return _.E(_.GM,Object.assign({},this.props,{className:[this.props.fma],bu:!0,jh:!this.state.WF,idomKey:"list",itemSize:void 0,getSize:this.getSize,version:`${this.state.version}_${(d=this.props.version)!=null?d:0}`}))}),this.F())};let b;this.Tg=(b=a.Tg)!=null?b:new Map}ma(a){if(this.props.Tg!==
a.Tg&&this.props.Tg){var b=this.Tg;this.Tg=this.props.Tg;for(const [c,d]of b.entries())this.Tg.set(c,d)}if(this.props.items!==a.items){b=new Set(this.props.items);a=new Set(a.items);for(const c of b)a.has(c)||this.j.add(c);for(const c of a)b.has(c)||(this.Tg.delete(c),this.j.delete(c));this.j.size&&_.Bk().then(()=>{this.I({WF:!1,version:this.state.version+1})})}}};_.OY.S="yt-dynamic-virtual-list";_.OY.T="ytDynamicVirtualListHost";
var pzb=class extends _.U{constructor(){super(...arguments);this.template=()=>_.E("host",{"aria-hidden":!0,style:{display:this.props.layout==="vertical"?"block":"inline-block"}},this.props.children)}Y(){this.props.onMount(this.props.layout==="vertical"?this.el.offsetHeight:this.el.offsetWidth)}};pzb.S="measurable-list-element";
}catch(e){_._DumpException(e)}
try{
var MEb,NEb,KEb;_.f0=function(a){if(!a)return!1;if(_.u(a,_.lA))return!0;var b=_.u(a,_.iA);return b?!b.isDisabled:(b=_.u(a,_.gt))?!b.isDisabled:_.u(a,_.dEb)||_.u(a,_.DZa)||_.u(a,_.dTa)||_.u(a,_.jA)||_.u(a,_.mX)||_.u(a,KEb)?!0:!1};
MEb=function({af:a,data:b,scrollable:c,height:d,focused:e},{ly:f,jh:g}){if(!b.items||b.items.length<=0||(!d||d<=0)&&c)return _.E("host",null);var h;let k;const m=(k=LEb[(h=b.layout)!=null?h:"OVERLAY_PANEL_ITEM_LIST_LAYOUT_VERTICAL"])!=null?k:"vertical",n=(q,v,w)=>_.dI({config:this.xb(q,v,w),renderer:q});h={["aria-labelledby"]:f};a&&(h.id=a);f||(h["aria-label"]=",");return _.E("host",Object.assign({},{className:"ytLrOverlayPanelItemListRendererCenter",id:this.props.zb},h),_.E(_.iK,{Sh:!0,currentIndex:this.fk(),
items:b.items,hb:_.f0,active:e,idomKey:"ttshelper"}),_.I(c&&m!=="horizontal",()=>{const q={alignment:_.kM,Ae:!0,jh:g,focused:e,hb:this.bO,items:b.items,aa:this.aa,selectedIndex:this.fk(),size:d||0,spacing:_.F("0.5rem"),Da:0,Ua:_.F("1.5rem")};return b.layout==="OVERLAY_PANEL_ITEM_LIST_LAYOUT_DYNAMIC_VERTICAL"?_.E(_.OY,Object.assign({},q,{className:"ytLrOverlayPanelItemListRendererDynamicVerticalList",idomKey:"scrollable-vertical-dynamic",layout:"vertical",Ya:({item:v,index:w,visibility:y})=>n(v,w,
y)})):_.E(_.GM,Object.assign({},q,{getSize:this.jW,idomKey:"scrollable-vertical",layout:"vertical",Ya:({item:v,index:w,visibility:y})=>n(v,w,y)}))},()=>_.E(_.JI,{layout:m,idomKey:"static",Ic:this.CX,aa:this.aa,focused:e,selectedIndex:this.fk()},_.SH(b.items,(q,v)=>n(q,v,"FULLY_VISIBLE")))))};NEb=function(a){return _.f0(a)};KEb=new _.O("subscriptionNotificationToggleButtonRenderer");var LEb={OVERLAY_PANEL_ITEM_LIST_LAYOUT_UNSPECIFIED:"vertical",OVERLAY_PANEL_ITEM_LIST_LAYOUT_VERTICAL:"vertical",OVERLAY_PANEL_ITEM_LIST_LAYOUT_HORIZONTAL:"horizontal",OVERLAY_PANEL_ITEM_LIST_LAYOUT_DYNAMIC_VERTICAL:"vertical"};var g0,OEb;g0=_.F("25.5rem");OEb=function(a,b){const c=a.props.data.items;if(!c)return-1;let d=-1;for(--b;b>=0;--b)if(!a.bO(c[b]))d=b;else if(d!==-1)break;return d};
_.h0=class extends _.U{constructor(a){super(a);this.template=MEb;this.cb=_.B.get(_.mC);this.xb=(b,c,d)=>{const e=this.props.focused&&this.fk()===c,f=this.state.tN,g=this.props.data.layout==="OVERLAY_PANEL_ITEM_LIST_LAYOUT_HORIZONTAL";var h,k=((h=this.props.data.items)==null?void 0:h.reduce((K,P)=>K+(_.u(P,_.iA)?1:0),0))||0;h=this.props.style==="fullscreen"?3:2;k=g?1:k>h?9:3;var m,n;h=((n=(m=this.props.data.items)==null?void 0:m.length)!=null?n:0)-1===c;m=_.u(b,_.gt);n=k===9;var q;const v=((q=_.u(b,
_.xA))==null?void 0:q.style)==="QR_CODE_RENDERER_STYLE_SQUEEZEBACK_LIST_ITEM";q=_.u(b,_.sDa);const w=_.A("useModernOverlayListItemStyle",!1)&&!_.A("isLimitedMemory",!1),y=_.u(b,_.lA),C=(y==null?void 0:y.subtitle)===void 0;(y==null?0:y.requiresParentFocus)&&this.props.focused&&this.I({KW:!0});let G;return{accountItemRenderer:{component:_.T_,props:{className:["ytLrOverlayPanelItemListRendererMenu",{ytLrOverlayPanelItemListRendererMenuLastChild:h,ytLrOverlayPanelItemListRendererMenuMenuBackground:!(m==
null?0:m.isDisabled)&&!w,ytLrOverlayPanelItemListRendererMenuTransparentMenuBackground:!(m==null?0:m.isDisabled)&&w}],focused:e,zb:f[c],qa:g0}},pinPairingRenderer:{component:_.V_},buttonRenderer:{component:_.PJ,props:{className:["ytLrOverlayPanelItemListRendererButton",{ytLrOverlayPanelItemListRendererButtonHorizontal:g,ytLrOverlayPanelItemListRendererButtonUseTransparentButtonBackground:w}],focused:e,shape:k,Ja:void 0,zb:f[c],qa:n?g0:void 0}},compactLinkRenderer:{component:_.UO,props:{className:["ytLrOverlayPanelItemListRendererMenu",
w?"ytLrOverlayPanelItemListRendererMenuTransparentMenuBackground":"ytLrOverlayPanelItemListRendererMenuMenuBackground",{ytLrOverlayPanelItemListRendererMenuLastChild:h}],focused:e,disabled:(y==null?void 0:y.requiresParentFocus)&&!this.state.KW,zb:f[c],qa:g0,Zj:!0,Eh:C}},counterfactualRenderer:{component:_.LM,props:{visibility:d}},dividerRenderer:{component:_.VO,props:{zb:f[c]}},overlayMessageRenderer:{component:_.YM,props:{className:["ytLrOverlayPanelItemListRendererMessage",{ytLrOverlayPanelItemListRendererCenteredMessage:(q==
null?void 0:q.style)==="OVERLAY_MESSAGE_STYLE_RICH_TEXT_LINK_QR_CODE_SCAN_PROMPT"||(q==null?void 0:q.style)==="OVERLAY_MESSAGE_STYLE_RICH_TEXT_LINK_QR_CODE_LINK"},{ytLrOverlayPanelItemListRendererBulletItem:(q==null?void 0:q.style)==="OVERLAY_MESSAGE_STYLE_BULLET_ITEM_WITH_SUBTITLE"}],zb:f[c],P1:this.props.HX}},paymentChallengeKeyboardRenderer:{component:_.d0,props:{className:"ytLrOverlayPanelItemListRendererMessage",focused:e,zb:f[c]}},playlistAddToOptionRenderer:{component:_.S_,props:{className:["ytLrOverlayPanelItemListRendererMenu",
w?"ytLrOverlayPanelItemListRendererMenuTransparentMenuBackground":"ytLrOverlayPanelItemListRendererMenuMenuBackground",{ytLrOverlayPanelItemListRendererMenuLastChild:h}],focused:e,zb:f[c],qa:g0}},playlistLoopButtonRenderer:{component:_.gK,props:{zb:f[c],Wh:9,className:["ytLrOverlayPanelItemListRendererMenu",w?"ytLrOverlayPanelItemListRendererMenuTransparentMenuBackground":"ytLrOverlayPanelItemListRendererMenuMenuBackground",{ytLrOverlayPanelItemListRendererMenuLastChild:h}],focused:e,qa:g0}},qrCodeRenderer:{component:_.fN,
props:{className:["ytLrOverlayPanelItemListRendererMessage",{ytLrOverlayPanelItemListRendererListItemQr:v}],width:((G=_.u(b,_.xA))==null?void 0:G.style)==="QR_CODE_RENDERER_STYLE_MAIN_SIDESHEET_CONTENT"?g0:void 0,zb:f[c]}},secondScreenActionRenderer:{component:_.e0,props:{className:"ytLrOverlayPanelItemListRendererMessage",zb:f[c]}},subscribeButtonRenderer:{component:_.ZW,props:{className:["ytLrOverlayPanelItemListRendererMenu",{ytLrOverlayPanelItemListRendererMenuLastChild:h}],focused:e,te:0,zb:f[c],
qa:g0,XO:c}},subscriptionNotificationToggleButtonRenderer:{component:_.XW,props:{className:["ytLrOverlayPanelItemListRendererMenu",{ytLrOverlayPanelItemListRendererMenuLastChild:h}],focused:e,zb:f[c],te:1,qa:g0}},toggleButtonRenderer:{component:_.UK,props:{className:["ytLrOverlayPanelItemListRendererButton",w?"ytLrOverlayPanelItemListRendererMenuTransparentMenuBackground":"ytLrOverlayPanelItemListRendererMenuMenuBackground",{ytLrOverlayPanelItemListRendererMenuLastChild:h}],preventAutoToggle:!0,shape:9,
iconPosition:"right",focused:e,zb:f[c],qa:n?g0:void 0}}}};this.j=b=>{const c=[];let d=!1;var e="";if(b){let f=e=b.length;for(let g=0;g<b.length;g++){const h=b[g];_.f0(h)?(e===b.length&&(e=g),f=g):c[g]=_.ln("ytlr_overlay_panel_item_list_renderer__aria-id");!d&&_.u(h,_.mX)&&(d=!0)}e=c.slice(0,e).concat(c.slice(f+1,b.length)).join(" ")}return{tN:c,ly:e,jh:d}};this.F=b=>{this.ya();_.Lo(b)};this.B=b=>{b=OEb(this,b);this.A!==b&&(b=this.state.tN[b])&&(b=document.getElementById(b.toString()),_.oI(this.cb,
b))};this.aa=b=>{b!==this.state.selectedIndex&&this.B(b);this.I({selectedIndex:b})};this.CX=b=>{const c=this.props.data.items;return!c||c.length<=b?!1:_.f0(c[b])};this.bO=b=>_.f0(b);this.jW=(b,c)=>{if(!b||_.u(b,_.RAb))return 0;if(_.u(b,_.iA))return _.F("3.75rem");if(_.u(b,_.rDa))return _.F("2rem");var d=_.u(b,_.mX);if(d)return _.BN(d,_.F("0.5rem"));if(d=_.u(b,_.sDa)){var e;a:{switch(d.style){case "OVERLAY_MESSAGE_STYLE_SUBSECTION_TITLE":b=c?2.5:1.5;break a;case "OVERLAY_MESSAGE_STYLE_RICH_TEXT_LINK_QR_CODE_SCAN_PROMPT":b=
2;break a}b=void 0}return(e=b)!=null?e:_.F("4rem")}if(_.u(b,_.tDa))return 11;if(b=_.u(b,_.xA)){e=_.h5a(b);a:switch(b.style){case "QR_CODE_RENDERER_STYLE_SQUEEZEBACK_LIST_ITEM":b=3;break a;default:b=0}e+=b}else e=_.F("4rem");return e};this.vz=_.M(b=>b?b.findIndex(NEb):-1);a=this.j(a.data.items);this.state=Object.assign({},{selectedIndex:this.props.data.selectedIndex},a)}Y(){this.on("listItemResizeAction",this.F)}ma(a){this.props.data.items===a.data.items||_.di(this.props.data.items,a.data.items)||
(a=this.j(this.props.data.items),this.I(a))}get A(){return this.state.selectedIndex===void 0?-1:OEb(this,this.state.selectedIndex)}fk(){return this.state.selectedIndex!==void 0?this.state.selectedIndex:Math.max(this.vz(this.props.data.items),0)}};_.h0.S="ytlr-overlay-panel-item-list-renderer";_.h0.T="ytLrOverlayPanelItemListRendererHost";_.Q(_.XO,_.h0);
}catch(e){_._DumpException(e)}
try{
_.p("jjTYge");

_.r();
}catch(e){_._DumpException(e)}
})(this._yttv);
// Google Inc.
