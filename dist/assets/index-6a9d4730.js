import{e as I,P as w,b as f,v as E,a as x}from"./index-adf31cb6.js";var P=globalThis&&globalThis.__extends||function(){var a=function(s,r){return a=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,n){e.__proto__=n}||function(e,n){for(var t in n)Object.prototype.hasOwnProperty.call(n,t)&&(e[t]=n[t])},a(s,r)};return function(s,r){if(typeof r!="function"&&r!==null)throw new TypeError("Class extends value "+String(r)+" is not a constructor or null");a(s,r);function e(){this.constructor=s}s.prototype=r===null?Object.create(r):(e.prototype=r.prototype,new e)}}(),A=function(a){P(s,a);function s(){return a!==null&&a.apply(this,arguments)||this}return s}(I);class j extends I{constructor(s,r){var e;if(super(),e=this,this._handleMessage=n=>{if(this._injectedProvider&&n.source===window||n.origin===this._providerUrl.origin&&n.source===this._popup){if(n.data.method==="connected"){const t=new w(n.data.params.publicKey);(!this._publicKey||!this._publicKey.equals(t))&&(this._publicKey&&!this._publicKey.equals(t)&&this._handleDisconnect(),this._publicKey=t,this._autoApprove=!!n.data.params.autoApprove,this.emit("connect",this._publicKey))}else if(n.data.method==="disconnected")this._handleDisconnect();else if((n.data.result||n.data.error)&&this._responsePromises.has(n.data.id)){const[t,o]=this._responsePromises.get(n.data.id);n.data.result?t(n.data.result):o(new Error(n.data.error))}}},this._handleConnect=()=>(this._handlerAdded||(this._handlerAdded=!0,window.addEventListener("message",this._handleMessage),window.addEventListener("beforeunload",this.disconnect)),this._injectedProvider?new Promise(n=>{this._sendRequest("connect",{}),n()}):(window.name="parent",this._popup=window.open(this._providerUrl.toString(),"_blank","location,resizable,width=460,height=675"),new Promise(n=>{this.once("connect",n)}))),this._handleDisconnect=()=>{this._handlerAdded&&(this._handlerAdded=!1,window.removeEventListener("message",this._handleMessage),window.removeEventListener("beforeunload",this.disconnect)),this._publicKey&&(this._publicKey=null,this.emit("disconnect")),this._responsePromises.forEach(([n,t],o)=>{this._responsePromises.delete(o),t("Wallet disconnected")})},this._sendRequest=async function(n,t){if(n!=="connect"&&!e.connected)throw new Error("Wallet not connected");const o=e._nextRequestId;return++e._nextRequestId,new Promise((l,c)=>{e._responsePromises.set(o,[l,c]),e._injectedProvider?e._injectedProvider.postMessage({jsonrpc:"2.0",id:o,method:n,params:{network:e._network,...t}}):(e._popup.postMessage({jsonrpc:"2.0",id:o,method:n,params:t},e._providerUrl.origin),e.autoApprove||e._popup.focus())})},this.connect=()=>(this._popup&&this._popup.close(),this._handleConnect()),this.disconnect=async function(){e._injectedProvider&&await e._sendRequest("disconnect",{}),e._popup&&e._popup.close(),e._handleDisconnect()},this.sign=async function(n,t){if(!(n instanceof Uint8Array))throw new Error("Data must be an instance of Uint8Array");const o=await e._sendRequest("sign",{data:n,display:t}),l=f.decode(o.signature),c=new w(o.publicKey);return{signature:l,publicKey:c}},this.signTransaction=async function(n){const t=await e._sendRequest("signTransaction",{message:f.encode(n.serializeMessage())}),o=f.decode(t.signature),l=new w(t.publicKey);return n.addSignature(l,o),n},this.signAllTransactions=async function(n){const t=await e._sendRequest("signAllTransactions",{messages:n.map(c=>f.encode(c.serializeMessage()))}),o=t.signatures.map(c=>f.decode(c)),l=new w(t.publicKey);return n=n.map((c,i)=>(c.addSignature(l,o[i]),c)),n},S(s))this._injectedProvider=s;else if(M(s))this._providerUrl=new URL(s),this._providerUrl.hash=new URLSearchParams({origin:window.location.origin,network:r}).toString();else throw new Error("provider parameter must be an injected provider or a URL string.");this._network=r,this._publicKey=null,this._autoApprove=!1,this._popup=null,this._handlerAdded=!1,this._nextRequestId=1,this._responsePromises=new Map}get publicKey(){return this._publicKey}get connected(){return this._publicKey!==null}get autoApprove(){return this._autoApprove}}function M(a){return typeof a=="string"}function S(a){return K(a)&&O(a.postMessage)}function K(a){return typeof a=="object"&&a!==null}function O(a){return typeof a=="function"}var R=globalThis&&globalThis.__extends||function(){var a=function(s,r){return a=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,n){e.__proto__=n}||function(e,n){for(var t in n)Object.prototype.hasOwnProperty.call(n,t)&&(e[t]=n[t])},a(s,r)};return function(s,r){if(typeof r!="function"&&r!==null)throw new TypeError("Class extends value "+String(r)+" is not a constructor or null");a(s,r);function e(){this.constructor=s}s.prototype=r===null?Object.create(r):(e.prototype=r.prototype,new e)}}(),_=globalThis&&globalThis.__awaiter||function(a,s,r,e){function n(t){return t instanceof r?t:new r(function(o){o(t)})}return new(r||(r=Promise))(function(t,o){function l(u){try{i(e.next(u))}catch(d){o(d)}}function c(u){try{i(e.throw(u))}catch(d){o(d)}}function i(u){u.done?t(u.value):n(u.value).then(l,c)}i((e=e.apply(a,s||[])).next())})},v=globalThis&&globalThis.__generator||function(a,s){var r={label:0,sent:function(){if(t[0]&1)throw t[1];return t[1]},trys:[],ops:[]},e,n,t,o;return o={next:l(0),throw:l(1),return:l(2)},typeof Symbol=="function"&&(o[Symbol.iterator]=function(){return this}),o;function l(i){return function(u){return c([i,u])}}function c(i){if(e)throw new TypeError("Generator is already executing.");for(;r;)try{if(e=1,n&&(t=i[0]&2?n.return:i[0]?n.throw||((t=n.return)&&t.call(n),0):n.next)&&!(t=t.call(n,i[1])).done)return t;switch(n=0,t&&(i=[i[0]&2,t.value]),i[0]){case 0:case 1:t=i;break;case 4:return r.label++,{value:i[1],done:!1};case 5:r.label++,n=i[1],i=[0];continue;case 7:i=r.ops.pop(),r.trys.pop();continue;default:if(t=r.trys,!(t=t.length>0&&t[t.length-1])&&(i[0]===6||i[0]===2)){r=0;continue}if(i[0]===3&&(!t||i[1]>t[0]&&i[1]<t[3])){r.label=i[1];break}if(i[0]===6&&r.label<t[1]){r.label=t[1],t=i;break}if(t&&r.label<t[2]){r.label=t[2],r.ops.push(i);break}t[2]&&r.ops.pop(),r.trys.pop();continue}i=s.call(a,r)}catch(u){i=[6,u],n=0}finally{e=t=0}if(i[0]&5)throw i[1];return{value:i[0]?i[1]:void 0,done:!0}}},W=function(a){R(s,a);function s(r,e,n){var t=a.call(this)||this;return t._instance=null,t.handleMessage=function(o){},t._sendRequest=function(o,l){return _(t,void 0,void 0,function(){return v(this,function(c){switch(c.label){case 0:return this._instance.sendRequest?[4,this._instance.sendRequest(o,l)]:[3,2];case 1:return[2,c.sent()];case 2:return this._instance._sendRequest?[4,this._instance._sendRequest(o,l)]:[3,4];case 3:return[2,c.sent()];case 4:throw new Error("Unsupported version of `@project-serum/sol-wallet-adapter`")}})})},t._handleConnect=function(){t.emit("connect")},t._handleDisconnect=function(){window.clearInterval(t._pollTimer),t.emit("disconnect")},t._network=e,t._provider=n,t}return Object.defineProperty(s.prototype,"publicKey",{get:function(){return this._instance.publicKey||null},enumerable:!1,configurable:!0}),Object.defineProperty(s.prototype,"connected",{get:function(){return this._instance.connected||!1},enumerable:!1,configurable:!0}),s.prototype.connect=function(){return _(this,void 0,void 0,function(){var r=this;return v(this,function(e){switch(e.label){case 0:return this._instance=new j(this._provider,this._network),this._instance.on("connect",this._handleConnect),this._instance.on("disconnect",this._handleDisconnect),this._pollTimer=window.setInterval(function(){var n,t;((t=(n=r._instance)===null||n===void 0?void 0:n._popup)===null||t===void 0?void 0:t.closed)!==!1&&r._handleDisconnect()},200),[4,this._instance.connect()];case 1:return e.sent(),[2]}})})},s.prototype.disconnect=function(){return _(this,void 0,void 0,function(){return v(this,function(r){switch(r.label){case 0:if(!this.connected)throw new Error("Wallet not connected");return this._instance.removeAllListeners("connect"),this._instance.removeAllListeners("disconnect"),[4,this._instance.disconnect()];case 1:return r.sent(),[2]}})})},s.prototype.signTransaction=function(r){return _(this,void 0,void 0,function(){var e;return v(this,function(n){switch(n.label){case 0:if(!this.connected)throw new Error("Wallet not connected");return[4,this._sendRequest("signTransaction",{message:f.encode(r)})];case 1:return e=n.sent(),[2,f.decode(e.signature)]}})})},s.prototype.signAllTransactions=function(r){return _(this,void 0,void 0,function(){var e;return v(this,function(n){switch(n.label){case 0:if(!this.connected)throw new Error("Wallet not connected");return[4,this._sendRequest("signAllTransactions",{messages:r.map(function(t){return f.encode(t)})})];case 1:return e=n.sent(),[2,e.signatures.map(function(t){return f.decode(t)})]}})})},s.prototype.signMessage=function(r,e){return e===void 0&&(e="hex"),_(this,void 0,void 0,function(){var n;return v(this,function(t){switch(t.label){case 0:if(!this.connected)throw new Error("Wallet not connected");return[4,this._instance.sign(r,e)];case 1:return n=t.sent().signature,[2,Uint8Array.from(n)]}})})},s}(A),k=globalThis&&globalThis.__extends||function(){var a=function(s,r){return a=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,n){e.__proto__=n}||function(e,n){for(var t in n)Object.prototype.hasOwnProperty.call(n,t)&&(e[t]=n[t])},a(s,r)};return function(s,r){if(typeof r!="function"&&r!==null)throw new TypeError("Class extends value "+String(r)+" is not a constructor or null");a(s,r);function e(){this.constructor=s}s.prototype=r===null?Object.create(r):(e.prototype=r.prototype,new e)}}(),b=globalThis&&globalThis.__assign||function(){return b=Object.assign||function(a){for(var s,r=1,e=arguments.length;r<e;r++){s=arguments[r];for(var n in s)Object.prototype.hasOwnProperty.call(s,n)&&(a[n]=s[n])}return a},b.apply(this,arguments)},g=globalThis&&globalThis.__awaiter||function(a,s,r,e){function n(t){return t instanceof r?t:new r(function(o){o(t)})}return new(r||(r=Promise))(function(t,o){function l(u){try{i(e.next(u))}catch(d){o(d)}}function c(u){try{i(e.throw(u))}catch(d){o(d)}}function i(u){u.done?t(u.value):n(u.value).then(l,c)}i((e=e.apply(a,s||[])).next())})},m=globalThis&&globalThis.__generator||function(a,s){var r={label:0,sent:function(){if(t[0]&1)throw t[1];return t[1]},trys:[],ops:[]},e,n,t,o;return o={next:l(0),throw:l(1),return:l(2)},typeof Symbol=="function"&&(o[Symbol.iterator]=function(){return this}),o;function l(i){return function(u){return c([i,u])}}function c(i){if(e)throw new TypeError("Generator is already executing.");for(;r;)try{if(e=1,n&&(t=i[0]&2?n.return:i[0]?n.throw||((t=n.return)&&t.call(n),0):n.next)&&!(t=t.call(n,i[1])).done)return t;switch(n=0,t&&(i=[i[0]&2,t.value]),i[0]){case 0:case 1:t=i;break;case 4:return r.label++,{value:i[1],done:!1};case 5:r.label++,n=i[1],i=[0];continue;case 7:i=r.ops.pop(),r.trys.pop();continue;default:if(t=r.trys,!(t=t.length>0&&t[t.length-1])&&(i[0]===6||i[0]===2)){r=0;continue}if(i[0]===3&&(!t||i[1]>t[0]&&i[1]<t[3])){r.label=i[1];break}if(i[0]===6&&r.label<t[1]){r.label=t[1],t=i;break}if(t&&r.label<t[2]){r.label=t[2],r.ops.push(i);break}t[2]&&r.ops.pop(),r.trys.pop();continue}i=s.call(a,r)}catch(u){i=[6,u],n=0}finally{e=t=0}if(i[0]&5)throw i[1];return{value:i[0]?i[1]:void 0,done:!0}}},T=function(a){k(s,a);function s(r,e){var n=this,t;return n=a.call(this)||this,n._publicKey=null,n._messageHandlers={},n.handleMessage=function(o){if(n._messageHandlers[o.id]){var l=n._messageHandlers[o.id],c=l.resolve,i=l.reject;delete n._messageHandlers[o.id],o.error?i(o.error):c(o.result)}},n._sendMessage=function(o){if(!n.connected)throw new Error("Wallet not connected");return new Promise(function(l,c){var i,u,d=E();n._messageHandlers[d]={resolve:l,reject:c},(u=(i=n._iframe)===null||i===void 0?void 0:i.contentWindow)===null||u===void 0||u.postMessage({channel:"solflareWalletAdapterToIframe",data:b({id:d},o)},"*")})},n._iframe=r,n._publicKey=new w((t=e?.toString)===null||t===void 0?void 0:t.call(e)),n}return Object.defineProperty(s.prototype,"publicKey",{get:function(){return this._publicKey||null},enumerable:!1,configurable:!0}),Object.defineProperty(s.prototype,"connected",{get:function(){return!0},enumerable:!1,configurable:!0}),s.prototype.connect=function(){return g(this,void 0,void 0,function(){return m(this,function(r){return[2]})})},s.prototype.disconnect=function(){return g(this,void 0,void 0,function(){return m(this,function(r){switch(r.label){case 0:return[4,this._sendMessage({method:"disconnect"})];case 1:return r.sent(),[2]}})})},s.prototype.signTransaction=function(r){return g(this,void 0,void 0,function(){var e,n;return m(this,function(t){switch(t.label){case 0:if(!this.connected)throw new Error("Wallet not connected");t.label=1;case 1:return t.trys.push([1,3,,4]),[4,this._sendMessage({method:"signTransaction",params:{message:f.encode(r)}})];case 2:return e=t.sent().signature,[2,f.decode(e)];case 3:throw n=t.sent(),console.log(n),new Error("Failed to sign transaction");case 4:return[2]}})})},s.prototype.signAllTransactions=function(r){return g(this,void 0,void 0,function(){var e,n;return m(this,function(t){switch(t.label){case 0:if(!this.connected)throw new Error("Wallet not connected");t.label=1;case 1:return t.trys.push([1,3,,4]),[4,this._sendMessage({method:"signAllTransactions",params:{messages:r.map(function(o){return f.encode(o)})}})];case 2:return e=t.sent().signatures,[2,e.map(function(o){return f.decode(o)})];case 3:throw n=t.sent(),console.log(n),new Error("Failed to sign transactions");case 4:return[2]}})})},s.prototype.signMessage=function(r,e){return e===void 0&&(e="hex"),g(this,void 0,void 0,function(){var n,t;return m(this,function(o){switch(o.label){case 0:if(!this.connected)throw new Error("Wallet not connected");o.label=1;case 1:return o.trys.push([1,3,,4]),[4,this._sendMessage({method:"signMessage",params:{data:r,display:e}})];case 2:return n=o.sent(),[2,Uint8Array.from(f.decode(n))];case 3:throw t=o.sent(),console.log(t),new Error("Failed to sign message");case 4:return[2]}})})},s}(A);function y(a){return a.version===void 0}var H=globalThis&&globalThis.__extends||function(){var a=function(s,r){return a=Object.setPrototypeOf||{__proto__:[]}instanceof Array&&function(e,n){e.__proto__=n}||function(e,n){for(var t in n)Object.prototype.hasOwnProperty.call(n,t)&&(e[t]=n[t])},a(s,r)};return function(s,r){if(typeof r!="function"&&r!==null)throw new TypeError("Class extends value "+String(r)+" is not a constructor or null");a(s,r);function e(){this.constructor=s}s.prototype=r===null?Object.create(r):(e.prototype=r.prototype,new e)}}(),h=globalThis&&globalThis.__awaiter||function(a,s,r,e){function n(t){return t instanceof r?t:new r(function(o){o(t)})}return new(r||(r=Promise))(function(t,o){function l(u){try{i(e.next(u))}catch(d){o(d)}}function c(u){try{i(e.throw(u))}catch(d){o(d)}}function i(u){u.done?t(u.value):n(u.value).then(l,c)}i((e=e.apply(a,s||[])).next())})},p=globalThis&&globalThis.__generator||function(a,s){var r={label:0,sent:function(){if(t[0]&1)throw t[1];return t[1]},trys:[],ops:[]},e,n,t,o;return o={next:l(0),throw:l(1),return:l(2)},typeof Symbol=="function"&&(o[Symbol.iterator]=function(){return this}),o;function l(i){return function(u){return c([i,u])}}function c(i){if(e)throw new TypeError("Generator is already executing.");for(;r;)try{if(e=1,n&&(t=i[0]&2?n.return:i[0]?n.throw||((t=n.return)&&t.call(n),0):n.next)&&!(t=t.call(n,i[1])).done)return t;switch(n=0,t&&(i=[i[0]&2,t.value]),i[0]){case 0:case 1:t=i;break;case 4:return r.label++,{value:i[1],done:!1};case 5:r.label++,n=i[1],i=[0];continue;case 7:i=r.ops.pop(),r.trys.pop();continue;default:if(t=r.trys,!(t=t.length>0&&t[t.length-1])&&(i[0]===6||i[0]===2)){r=0;continue}if(i[0]===3&&(!t||i[1]>t[0]&&i[1]<t[3])){r.label=i[1];break}if(i[0]===6&&r.label<t[1]){r.label=t[1],t=i;break}if(t&&r.label<t[2]){r.label=t[2],r.ops.push(i);break}t[2]&&r.ops.pop(),r.trys.pop();continue}i=s.call(a,r)}catch(u){i=[6,u],n=0}finally{e=t=0}if(i[0]&5)throw i[1];return{value:i[0]?i[1]:void 0,done:!0}}},q=globalThis&&globalThis.__values||function(a){var s=typeof Symbol=="function"&&Symbol.iterator,r=s&&a[s],e=0;if(r)return r.call(a);if(a&&typeof a.length=="number")return{next:function(){return a&&e>=a.length&&(a=void 0),{value:a&&a[e++],done:!a}}};throw new TypeError(s?"Object is not iterable.":"Symbol.iterator is not defined.")},U=function(a){H(s,a);function s(r){var e=a.call(this)||this;return e._network="mainnet-beta",e._provider=null,e._adapterInstance=null,e._element=null,e._iframe=null,e._connectHandler=null,e._flutterHandlerInterval=null,e._handleEvent=function(n){var t,o,l,c;switch(n.type){case"connect_native_web":{e._collapseIframe(),e._adapterInstance=new W(e._iframe,e._network,((t=n.data)===null||t===void 0?void 0:t.provider)||e._provider||"https://solflare.com/provider"),e._adapterInstance.on("connect",e._webConnected),e._adapterInstance.on("disconnect",e._webDisconnected),e._adapterInstance.connect(),e._setPreferredAdapter("native_web");return}case"connect":{e._collapseIframe(),e._adapterInstance=new T(e._iframe,((o=n.data)===null||o===void 0?void 0:o.publicKey)||""),e._adapterInstance.connect(),e._setPreferredAdapter((l=n.data)===null||l===void 0?void 0:l.adapter),e._connectHandler&&(e._connectHandler.resolve(),e._connectHandler=null),e.emit("connect",e.publicKey);return}case"disconnect":{e._connectHandler&&(e._connectHandler.reject(),e._connectHandler=null),e._disconnected(),e.emit("disconnect");return}case"accountChanged":{!((c=n.data)===null||c===void 0)&&c.publicKey?(e._adapterInstance=new T(e._iframe,n.data.publicKey),e._adapterInstance.connect(),e.emit("accountChanged",e.publicKey)):e.emit("accountChanged",void 0);return}case"collapse":{e._collapseIframe();return}default:return}},e._handleResize=function(n){n.resizeMode==="full"?n.params.mode==="fullscreen"?e._expandIframe():n.params.mode==="hide"&&e._collapseIframe():n.resizeMode==="coordinates"&&e._iframe&&(e._iframe.style.top=isFinite(n.params.top)?"".concat(n.params.top,"px"):"",e._iframe.style.bottom=isFinite(n.params.bottom)?"".concat(n.params.bottom,"px"):"",e._iframe.style.left=isFinite(n.params.left)?"".concat(n.params.left,"px"):"",e._iframe.style.right=isFinite(n.params.right)?"".concat(n.params.right,"px"):"",e._iframe.style.width=isFinite(n.params.width)?"".concat(n.params.width,"px"):n.params.width,e._iframe.style.height=isFinite(n.params.height)?"".concat(n.params.height,"px"):n.params.height)},e._handleMessage=function(n){var t;if(((t=n.data)===null||t===void 0?void 0:t.channel)==="solflareIframeToWalletAdapter"){var o=n.data.data||{};o.type==="event"?e._handleEvent(o.event):o.type==="resize"?e._handleResize(o):o.type==="response"&&e._adapterInstance&&e._adapterInstance.handleMessage(o)}},e._removeElement=function(){e._flutterHandlerInterval!==null&&(clearInterval(e._flutterHandlerInterval),e._flutterHandlerInterval=null),e._element&&(e._element.remove(),e._element=null)},e._removeDanglingElements=function(){var n,t,o=document.getElementsByClassName("solflare-wallet-adapter-iframe");try{for(var l=q(o),c=l.next();!c.done;c=l.next()){var i=c.value;i.parentElement&&i.remove()}}catch(u){n={error:u}}finally{try{c&&!c.done&&(t=l.return)&&t.call(l)}finally{if(n)throw n.error}}},e._injectElement=function(){e._removeElement(),e._removeDanglingElements();var n="".concat(s.IFRAME_URL,"?cluster=").concat(encodeURIComponent(e._network),"&origin=").concat(encodeURIComponent(window.location.origin),"&version=1"),t=e._getPreferredAdapter();t&&(n+="&adapter=".concat(encodeURIComponent(t))),e._element=document.createElement("div"),e._element.className="solflare-wallet-adapter-iframe",e._element.innerHTML=`
      <iframe src='`.concat(n,`' style='position: fixed; top: 0; bottom: 0; left: 0; right: 0; width: 100%; height: 100%; border: none; border-radius: 0; z-index: 99999; color-scheme: auto;' allowtransparency='true'></iframe>
    `),document.body.appendChild(e._element),e._iframe=e._element.querySelector("iframe"),window.fromFlutter=e._handleMobileMessage,e._flutterHandlerInterval=setInterval(function(){window.fromFlutter=e._handleMobileMessage},100),window.addEventListener("message",e._handleMessage,!1)},e._collapseIframe=function(){e._iframe&&(e._iframe.style.top="",e._iframe.style.right="",e._iframe.style.height="2px",e._iframe.style.width="2px")},e._expandIframe=function(){e._iframe&&(e._iframe.style.top="0px",e._iframe.style.bottom="0px",e._iframe.style.left="0px",e._iframe.style.right="0px",e._iframe.style.width="100%",e._iframe.style.height="100%")},e._getPreferredAdapter=function(){return localStorage&&localStorage.getItem("solflarePreferredWalletAdapter")||null},e._setPreferredAdapter=function(n){localStorage&&n&&localStorage.setItem("solflarePreferredWalletAdapter",n)},e._clearPreferredAdapter=function(){localStorage&&localStorage.removeItem("solflarePreferredWalletAdapter")},e._webConnected=function(){e._connectHandler&&(e._connectHandler.resolve(),e._connectHandler=null),e.emit("connect",e.publicKey)},e._webDisconnected=function(){e._connectHandler&&(e._connectHandler.reject(),e._connectHandler=null),e._disconnected(),e.emit("disconnect")},e._disconnected=function(){window.removeEventListener("message",e._handleMessage,!1),e._removeElement(),e._clearPreferredAdapter(),e._adapterInstance=null},e._handleMobileMessage=function(n){var t,o;(o=(t=e._iframe)===null||t===void 0?void 0:t.contentWindow)===null||o===void 0||o.postMessage({channel:"solflareMobileToIframe",data:n},"*")},r?.network&&(e._network=r?.network),r?.provider&&(e._provider=r?.provider),e}return Object.defineProperty(s.prototype,"publicKey",{get:function(){var r;return((r=this._adapterInstance)===null||r===void 0?void 0:r.publicKey)||null},enumerable:!1,configurable:!0}),Object.defineProperty(s.prototype,"isConnected",{get:function(){var r;return!!(!((r=this._adapterInstance)===null||r===void 0)&&r.connected)},enumerable:!1,configurable:!0}),Object.defineProperty(s.prototype,"connected",{get:function(){return this.isConnected},enumerable:!1,configurable:!0}),Object.defineProperty(s.prototype,"autoApprove",{get:function(){return!1},enumerable:!1,configurable:!0}),s.prototype.connect=function(){return h(this,void 0,void 0,function(){var r=this;return p(this,function(e){switch(e.label){case 0:return this.connected?[2]:(this._injectElement(),[4,new Promise(function(n,t){r._connectHandler={resolve:n,reject:t}})]);case 1:return e.sent(),[2]}})})},s.prototype.disconnect=function(){return h(this,void 0,void 0,function(){return p(this,function(r){switch(r.label){case 0:return this._adapterInstance?[4,this._adapterInstance.disconnect()]:[2];case 1:return r.sent(),this._disconnected(),this.emit("disconnect"),[2]}})})},s.prototype.signTransaction=function(r){return h(this,void 0,void 0,function(){var e,n,t,o,l=this;return p(this,function(c){switch(c.label){case 0:if(!this.connected)throw new Error("Wallet not connected");return e=y(r)?r.serializeMessage():r.message.serialize(),[4,this._adapterInstance.signTransaction(e)];case 1:return n=c.sent(),y(r)?r.addSignature(this.publicKey,x.Buffer.from(n)):(t=r.message.staticAccountKeys.slice(0,r.message.header.numRequiredSignatures),o=t.findIndex(function(i){return i.equals(l.publicKey)}),o>=0&&(r.signatures[o]=n)),[2,r]}})})},s.prototype.signAllTransactions=function(r){return h(this,void 0,void 0,function(){var e,n,t,o,l,c,i=this;return p(this,function(u){switch(u.label){case 0:if(!this.connected)throw new Error("Wallet not connected");return e=r.map(function(d){return y(d)?d.serializeMessage():d.message.serialize()}),[4,this._adapterInstance.signAllTransactions(e)];case 1:for(n=u.sent(),t=0;t<r.length;t++)o=r[t],y(o)?o.addSignature(this.publicKey,x.Buffer.from(n[t])):(l=o.message.staticAccountKeys.slice(0,o.message.header.numRequiredSignatures),c=l.findIndex(function(d){return d.equals(i.publicKey)}),c>=0&&(o.signatures[c]=n[t]));return[2,r]}})})},s.prototype.signMessage=function(r,e){return e===void 0&&(e="utf8"),h(this,void 0,void 0,function(){return p(this,function(n){switch(n.label){case 0:if(!this.connected)throw new Error("Wallet not connected");return[4,this._adapterInstance.signMessage(r,e)];case 1:return[2,n.sent()]}})})},s.prototype.sign=function(r,e){return e===void 0&&(e="utf8"),h(this,void 0,void 0,function(){return p(this,function(n){switch(n.label){case 0:return[4,this.signMessage(r,e)];case 1:return[2,n.sent()]}})})},s.prototype.detectWallet=function(r){var e;return r===void 0&&(r=10),h(this,void 0,void 0,function(){return p(this,function(n){return window.SolflareApp||!((e=window.solflare)===null||e===void 0)&&e.isSolflare?[2,!0]:[2,new Promise(function(t){var o,l;o=setInterval(function(){var c;(window.SolflareApp||!((c=window.solflare)===null||c===void 0)&&c.isSolflare)&&(clearInterval(o),clearTimeout(l),t(!0))},500),l=setTimeout(function(){clearInterval(o),t(!1)},r*1e3)})]})})},s.IFRAME_URL="https://connect.solflare.com/",s}(I);export{U as default};