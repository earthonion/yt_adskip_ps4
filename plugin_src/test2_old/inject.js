! function() {
    "use strict";
    var markerId = '__MINIHOOK_VISIBLE';
    if (window.__MINIHOOK_JS_RAN) {
      if (!document.getElementById(markerId)) {
        window.__MINIHOOK_JS_RAN = false;
      } else {
        return;
      }
    }
    if (document.getElementById(markerId)) {
      window.__MINIHOOK_JS_RAN = true;
      return;
    }
    window.__MINIHOOK_JS_RAN = true;
    
    function e(e, t) {
        (null == t || t > e.length) && (t = e.length);
        for (var n = 0, o = Array(t); n < t; n++) o[n] = e[n];
        return o
    }

    function t(e, t, n, o, i, r, a) {
        try {
            var l = e[r](a),
                s = l.value
        } catch (e) {
            return void n(e)
        }
        l.done ? t(s) : Promise.resolve(s).then(o, i)
    }

    function n(e, t) {
        var n = "undefined" != typeof Symbol && e[Symbol.iterator] || e["@@iterator"];
        if (!n) {
            if (Array.isArray(e) || (n = s(e)) || t && e && "number" == typeof e.length) {
                n && (e = n);
                var o = 0,
                    i = function() {};
                return {
                    s: i,
                    n: function() {
                        return o >= e.length ? {
                            done: !0
                        } : {
                            done: !1,
                            value: e[o++]
                        }
                    },
                    e: function(e) {
                        throw e
                    },
                    f: i
                }
            }
            throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")
        }
        var r, a = !0,
            l = !1;
        return {
            s: function() {
                n = n.call(e)
            },
            n: function() {
                var e = n.next();
                return a = e.done, e
            },
            e: function(e) {
                l = !0, r = e
            },
            f: function() {
                try {
                    a || null == n.return || n.return()
                } finally {
                    if (l) throw r
                }
            }
        }
    }

    function o(e, t, n) {
        return (t = function(e) {
            var t = function(e, t) {
                if ("object" != typeof e || !e) return e;
                var n = e[Symbol.toPrimitive];
                if (void 0 !== n) {
                    var o = n.call(e, t || "default");
                    if ("object" != typeof o) return o;
                    throw new TypeError("@@toPrimitive must return a primitive value.")
                }
                return ("string" === t ? String : Number)(e)
            }(e, "string");
            return "symbol" == typeof t ? t : t + ""
        }(t)) in e ? Object.defineProperty(e, t, {
            value: n,
            enumerable: !0,
            configurable: !0,
            writable: !0
        }) : e[t] = n, e
    }

    function i() {
        /*! regenerator-runtime -- Copyright (c) 2014-present, Facebook, Inc. -- license (MIT): https://github.com/babel/babel/blob/main/packages/babel-helpers/LICENSE */
        var e, t, n = "function" == typeof Symbol ? Symbol : {},
            o = n.iterator || "@@iterator",
            a = n.toStringTag || "@@toStringTag";

        function l(n, o, i, a) {
            var l = o && o.prototype instanceof c ? o : c,
                u = Object.create(l.prototype);
            return r(u, "_invoke", function(n, o, i) {
                var r, a, l, c = 0,
                    u = i || [],
                    d = !1,
                    p = {
                        p: 0,
                        n: 0,
                        v: e,
                        a: m,
                        f: m.bind(e, 4),
                        d: function(t, n) {
                            return r = t, a = 0, l = e, p.n = n, s
                        }
                    };

                function m(n, o) {
                    for (a = n, l = o, t = 0; !d && c && !i && t < u.length; t++) {
                        var i, r = u[t],
                            m = p.p,
                            f = r[2];
                        n > 3 ? (i = f === o) && (l = r[(a = r[4]) ? 5 : (a = 3, 3)], r[4] = r[5] = e) : r[0] <= m && ((i = n < 2 && m < r[1]) ? (a = 0, p.v = o, p.n = r[1]) : m < f && (i = n < 3 || r[0] > o || o > f) && (r[4] = n, r[5] = o, p.n = f, a = 0))
                    }
                    if (i || n > 1) return s;
                    throw d = !0, o
                }
                return function(i, u, f) {
                    if (c > 1) throw TypeError("Generator is already running");
                    for (d && 1 === u && m(u, f), a = u, l = f;
                        (t = a < 2 ? e : l) || !d;) {
                        r || (a ? a < 3 ? (a > 1 && (p.n = -1), m(a, l)) : p.n = l : p.v = l);
                        try {
                            if (c = 2, r) {
                                if (a || (i = "next"), t = r[i]) {
                                    if (!(t = t.call(r, l))) throw TypeError("iterator result is not an object");
                                    if (!t.done) return t;
                                    l = t.value, a < 2 && (a = 0)
                                } else 1 === a && (t = r.return) && t.call(r), a < 2 && (l = TypeError("The iterator does not provide a '" + i + "' method"), a = 1);
                                r = e
                            } else if ((t = (d = p.n < 0) ? l : n.call(o, p)) !== s) break
                        } catch (t) {
                            r = e, a = 1, l = t
                        } finally {
                            c = 1
                        }
                    }
                    return {
                        value: t,
                        done: d
                    }
                }
            }(n, i, a), !0), u
        }
        var s = {};

        function c() {}

        function u() {}

        function d() {}
        t = Object.getPrototypeOf;
        var p = [][o] ? t(t([][o]())) : (r(t = {}, o, function() {
                return this
            }), t),
            m = d.prototype = c.prototype = Object.create(p);

        function f(e) {
            return Object.setPrototypeOf ? Object.setPrototypeOf(e, d) : (e.__proto__ = d, r(e, a, "GeneratorFunction")), e.prototype = Object.create(m), e
        }
        return u.prototype = d, r(m, "constructor", d), r(d, "constructor", u), u.displayName = "GeneratorFunction", r(d, a, "GeneratorFunction"), r(m), r(m, a, "Generator"), r(m, o, function() {
            return this
        }), r(m, "toString", function() {
            return "[object Generator]"
        }), (i = function() {
            return {
                w: l,
                m: f
            }
        })()
    }

    function r(e, t, n, o) {
        var i = Object.defineProperty;
        try {
            i({}, "", {})
        } catch (e) {
            i = 0
        }
        r = function(e, t, n, o) {
            if (t) i ? i(e, t, {
                value: n,
                enumerable: !o,
                configurable: !o,
                writable: !o
            }) : e[t] = n;
            else {
                function a(t, n) {
                    r(e, t, function(e) {
                        return this._invoke(t, n, e)
                    })
                }
                a("next", 0), a("throw", 1), a("return", 2)
            }
        }, r(e, t, n, o)
    }

    function a(e, t) {
        return function(e) {
            if (Array.isArray(e)) return e
        }(e) || function(e, t) {
            var n = null == e ? null : "undefined" != typeof Symbol && e[Symbol.iterator] || e["@@iterator"];
            if (null != n) {
                var o, i, r, a, l = [],
                    s = !0,
                    c = !1;
                try {
                    if (r = (n = n.call(e)).next, 0 === t) {
                        if (Object(n) !== n) return;
                        s = !1
                    } else
                        for (; !(s = (o = r.call(n)).done) && (l.push(o.value), l.length !== t); s = !0);
                } catch (e) {
                    c = !0, i = e
                } finally {
                    try {
                        if (!s && null != n.return && (a = n.return(), Object(a) !== a)) return
                    } finally {
                        if (c) throw i
                    }
                }
                return l
            }
        }(e, t) || s(e, t) || function() {
            throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")
        }()
    }

    function l(e) {
        return l = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
            return typeof e
        } : function(e) {
            return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
        }, l(e)
    }

    function s(t, n) {
        if (t) {
            if ("string" == typeof t) return e(t, n);
            var o = {}.toString.call(t).slice(8, -1);
            return "Object" === o && t.constructor && (o = t.constructor.name), "Map" === o || "Set" === o ? Array.from(t) : "Arguments" === o || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(o) ? e(t, n) : void 0
        }
    }! function() {
        function e(e) {
            return void 0 === e ? 0 : Number(e)
        }

        function t(e, t) {
            return e !== t && !(isNaN(e) && isNaN(t))
        }
        self.DOMRect = function(n, o, i, r) {
            var a, l, s, c, u, d, p, m;
            a = e(n), l = e(o), s = e(i), c = e(r), Object.defineProperties(this, {
                x: {
                    get: function() {
                        return a
                    },
                    set: function(e) {
                        t(a, e) && (a = e, u = d = void 0)
                    },
                    enumerable: !0
                },
                y: {
                    get: function() {
                        return l
                    },
                    set: function(e) {
                        t(l, e) && (l = e, p = m = void 0)
                    },
                    enumerable: !0
                },
                width: {
                    get: function() {
                        return s
                    },
                    set: function(e) {
                        t(s, e) && (s = e, u = d = void 0)
                    },
                    enumerable: !0
                },
                height: {
                    get: function() {
                        return c
                    },
                    set: function(e) {
                        t(c, e) && (c = e, p = m = void 0)
                    },
                    enumerable: !0
                },
                left: {
                    get: function() {
                        return void 0 === u && (u = a + Math.min(0, s)), u
                    },
                    enumerable: !0
                },
                right: {
                    get: function() {
                        return void 0 === d && (d = a + Math.max(0, s)), d
                    },
                    enumerable: !0
                },
                top: {
                    get: function() {
                        return void 0 === p && (p = l + Math.min(0, c)), p
                    },
                    enumerable: !0
                },
                bottom: {
                    get: function() {
                        return void 0 === m && (m = l + Math.max(0, c)), m
                    },
                    enumerable: !0
                }
            })
        }
    }();
    var c, u = "ytaf-configuration",
        d = {
            enableAdBlock: !0,
            enableSponsorBlock: !0,
            sponsorBlockManualSkips: ["intro", "outro", "filler"],
            enableSponsorBlockSponsor: !0,
            enableSponsorBlockIntro: !0,
            enableSponsorBlockOutro: !0,
            enableSponsorBlockInteraction: !0,
            enableSponsorBlockSelfPromo: !0,
            enableSponsorBlockPreview: !0,
            enableSponsorBlockMusicOfftopic: !0,
            enableSponsorBlockFiller: !1,
            videoSpeed: 1,
            enableDeArrow: !0,
            enableDeArrowThumbnails: !1,
            focusContainerColor: "#0f0f0f",
            routeColor: "#0f0f0f",
            enableFixedUI: !0,
            enableHqThumbnails: !1,
            enableChapters: !0,
            enableLongPress: !0,
            enableShorts: !0,
            dontCheckUpdateUntil: 0,
            enableWhoIsWatchingMenu: !1
        };
    try {
        c = JSON.parse(window.localStorage[u])
    } catch (W) {
        console.warn("Config read failed:", W), c = d
    }

    function p(e) {
        return void 0 === c[e] && (console.warn("Populating key", e, "with default value", d[e]), c[e] = d[e]), c[e]
    }

    function m(e, t) {
        console.info("Setting key", e, "to", t), c[e] = t, window.localStorage[u] = JSON.stringify(c), f.dispatchEvent(new CustomEvent("configChange", {
            detail: {
                key: e,
                value: t
            }
        }))
    }
    var f = {
        listeners: {},
        addEventListener(e, t) {
            this.listeners[e] || (this.listeners[e] = []), this.listeners[e].push(t)
        },
        removeEventListener(e, t) {
            this.listeners[e] && (this.listeners[e] = this.listeners[e].filter(e => e !== t))
        },
        dispatchEvent(e) {
            var t = e.type;
            this.listeners[t] && this.listeners[t].forEach(t => t.call(this, e))
        }
    };

    function v(e, t, n) {
        var o = {
            openPopupAction: {
                popupType: "TOAST",
                popup: {
                    overlayToastRenderer: {
                        title: {
                            simpleText: e
                        },
                        subtitle: {
                            simpleText: t
                        }
                    }
                }
            }
        };
        n && (o.openPopupAction.popup.overlayToastRenderer.image.thumbnails = n), E(o)
    }

    function h(e, t, n, o, i) {
        var r = "string" == typeof e ? {
                title: e,
                subtitle: ""
            } : e,
            a = {
                openPopupAction: {
                    popupType: "MODAL",
                    popup: {
                        overlaySectionRenderer: {
                            overlay: {
                                overlayTwoPanelRenderer: {
                                    actionPanel: {
                                        overlayPanelRenderer: {
                                            header: {
                                                overlayPanelHeaderRenderer: {
                                                    title: {
                                                        simpleText: r.title
                                                    }
                                                }
                                            },
                                            content: {
                                                overlayPanelItemListRenderer: {
                                                    items: t,
                                                    selectedIndex: n
                                                }
                                            }
                                        }
                                    },
                                    backButton: {
                                        buttonRenderer: {
                                            accessibilityData: {
                                                accessibilityData: {
                                                    label: "Back"
                                                }
                                            },
                                            command: {
                                                signalAction: {
                                                    signal: "POPUP_BACK"
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            dismissalCommand: {
                                signalAction: {
                                    signal: "POPUP_BACK"
                                }
                            }
                        }
                    },
                    uniqueId: o
                }
            };
        r.subtitle && (a.openPopupAction.popup.overlaySectionRenderer.overlay.overlayTwoPanelRenderer.actionPanel.overlayPanelRenderer.header.overlayPanelHeaderRenderer.subtitle = {
            simpleText: r.subtitle
        }), i && (a.openPopupAction.shouldMatchUniqueId = !0, a.openPopupAction.updateAction = !0), E(a)
    }

    function g(e, t, n) {
        var o = {
            compactLinkRenderer: {
                serviceEndpoint: {
                    commandExecutorCommand: {
                        commands: n
                    }
                }
            }
        };
        return e && (o.compactLinkRenderer.title = {
            simpleText: e.title
        }), e.subtitle && (o.compactLinkRenderer.subtitle = {
            simpleText: e.subtitle
        }), t && (o.compactLinkRenderer.icon = {
            iconType: t.icon
        }), t && t.secondaryIcon && (o.compactLinkRenderer.secondaryIcon = {
            iconType: t.secondaryIcon
        }), o
    }

    function y(e, t, n, o, i) {
        return {
            timelyActionRenderer: {
                actionButtons: [{
                    buttonRenderer: {
                        isDisabled: !1,
                        text: {
                            runs: [{
                                text: e
                            }]
                        },
                        icon: {
                            iconType: t
                        },
                        trackingParams: null,
                        command: n
                    }
                }],
                triggerTimeMs: o,
                timeoutMs: i,
                type: ""
            }
        }
    }

    function b(e) {
        return {
            clickTrackingParams: null,
            showMenuCommand: {
                contentId: e.videoId,
                thumbnail: {
                    thumbnails: e.thumbnails
                },
                title: {
                    simpleText: e.title
                },
                subtitle: {
                    simpleText: e.subtitle
                },
                menu: {
                    menuRenderer: {
                        items: [{
                            menuNavigationItemRenderer: {
                                text: {
                                    runs: [{
                                        text: "Play"
                                    }]
                                },
                                navigationEndpoint: {
                                    clickTrackingParams: null,
                                    watchEndpoint: e.watchEndpointData
                                },
                                trackingParams: null
                            }
                        }, {
                            menuServiceItemRenderer: {
                                text: {
                                    runs: [{
                                        text: "Save to Watch Later"
                                    }]
                                },
                                serviceEndpoint: {
                                    clickTrackingParams: null,
                                    playlistEditEndpoint: {
                                        playlistId: "WL",
                                        actions: [{
                                            addedVideoId: e.videoId,
                                            action: "ACTION_ADD_VIDEO"
                                        }]
                                    }
                                },
                                trackingParams: null
                            }
                        }, {
                            menuNavigationItemRenderer: {
                                text: {
                                    runs: [{
                                        text: "Save to playlist"
                                    }]
                                },
                                navigationEndpoint: {
                                    clickTrackingParams: null,
                                    addToPlaylistEndpoint: {
                                        videoId: e.videoId
                                    }
                                },
                                trackingParams: null
                            }
                        }],
                        trackingParams: null,
                        accessibility: {
                            accessibilityData: {
                                label: "Video options"
                            }
                        }
                    }
                }
            }
        }
    }

    function w(e, t) {
        for (var n = [], o = 0, i = 0, r = [{
                name: "Ad block",
                icon: "DOLLAR_SIGN",
                value: "enableAdBlock"
            }, {
                name: "SponsorBlock",
                icon: "MONEY_HAND",
                value: "enableSponsorBlock"
            }, {
                name: "Manual SponsorBlock Segment Skip",
                icon: "DOLLAR_SIGN",
                value: null,
                options: [{
                    name: "Skip Sponsor Segments",
                    icon: "MONEY_HEART",
                    value: "sponsor"
                }, {
                    name: "Skip Intro Segments",
                    icon: "PLAY_CIRCLE",
                    value: "intro"
                }, {
                    name: "Skip Outro Segments",
                    value: "outro"
                }, {
                    name: "Skip Interaction Reminder Segments",
                    value: "interaction"
                }, {
                    name: "Skip Self-Promotion Segments",
                    value: "selfpromo"
                }, {
                    name: "Skip Preview/Recap Segments",
                    value: "preview"
                }, {
                    name: "Skip Tangents/Jokes Segments",
                    value: "filler"
                }, {
                    name: "Skip Off-Topic Music Segments",
                    value: "music_offtopic"
                }]
            }, {
                name: "Skip Sponsor Segments",
                icon: "MONEY_HEART",
                value: "enableSponsorBlockSponsor"
            }, {
                name: "Skip Intro Segments",
                icon: "PLAY_CIRCLE",
                value: "enableSponsorBlockIntro"
            }, {
                name: "Skip Outro Segments",
                value: "enableSponsorBlockOutro"
            }, {
                name: "Skip Interaction Reminder Segments",
                value: "enableSponsorBlockInteraction"
            }, {
                name: "Skip Self-Promotion Segments",
                value: "enableSponsorBlockSelfPromo"
            }, {
                name: "Skip Preview/Recap Segments",
                value: "enableSponsorBlockPreview"
            }, {
                name: "Skip Tangents/Jokes Segments",
                value: "enableSponsorBlockFiller"
            }, {
                name: "Skip Off-Topic Music Segments",
                value: "enableSponsorBlockMusicOfftopic"
            }, {
                name: "DeArrow",
                icon: "VISIBILITY_OFF",
                value: "enableDeArrow"
            }, {
                name: "DeArrow Thumbnails",
                icon: "TV",
                value: "enableDeArrowThumbnails"
            }, {
                name: "Fix UI",
                icon: "STAR",
                value: "enableFixedUI"
            }, {
                name: "High Quality Thumbnails",
                icon: "VIDEO_QUALITY",
                value: "enableHqThumbnails"
            }, {
                name: "Long Press",
                value: "enableLongPress"
            }, {
                name: "Shorts",
                icon: "YOUTUBE_SHORTS_FILL_24",
                value: "enableShorts"
            }, {
                name: "Who's Watching Menu",
                icon: "ACCOUNT_CIRCLE",
                value: "enableWhoIsWatchingMenu"
            }]; i < r.length; i++) {
            var a = r[i],
                l = a.value ? p(a.value) : null;
            n.push(g({
                title: a.name,
                subtitle: a.subtitle
            }, {
                icon: a.icon ? a.icon : "CHEVRON_DOWN",
                secondaryIcon: null === l ? "CHEVRON_RIGHT" : l ? "CHECK_BOX" : "CHECK_BOX_OUTLINE_BLANK"
            }, null !== l ? [{
                setClientSettingEndpoint: {
                    settingDatas: [{
                        clientSettingEnum: {
                            item: a.value
                        },
                        boolValue: !p(a.value)
                    }]
                }
            }, {
                customAction: {
                    action: "SETTINGS_UPDATE",
                    parameters: [o]
                }
            }] : [{
                customAction: {
                    action: "OPTIONS_SHOW",
                    parameters: {
                        options: a.options,
                        selectedIndex: 0,
                        update: !1
                    }
                }
            }])), o++
        }
        h({
            title: "TizenTube Settings",
            subtitle: "Made by Reis Can (reisxd) with ❤️"
        }, n, t && t.length > 0 ? t[0] : 0, "tt-settings", e)
    }
    var S = setInterval(() => {
        document.querySelector("video") && (! function() {
            document.querySelector("video").addEventListener("canplay", () => {
                document.getElementsByTagName("video")[0].playbackRate = p("videoSpeed")
            });
            var e = e => {
                if (406 == e.keyCode || 191 == e.keyCode) return e.preventDefault(), e.stopPropagation(), "keydown" !== e.type || (k(), !1)
            };
            document.addEventListener("keydown", e, !0), document.addEventListener("keypress", e, !0), document.addEventListener("keyup", e, !0)
        }(), clearInterval(S))
    }, 1e3);

    function k() {
        for (var e = p("videoSpeed"), t = 0, n = [], o = .25; o <= 4; o += .25) n.push(g({
            title: `${o}x`
        }, null, [{
            signalAction: {
                signal: "POPUP_BACK"
            }
        }, {
            setClientSettingEndpoint: {
                settingDatas: [{
                    clientSettingEnum: {
                        item: "videoSpeed"
                    },
                    intValue: o.toString()
                }]
            }
        }, {
            customAction: {
                action: "SET_PLAYER_SPEED",
                parameters: o.toString()
            }
        }])), e === o && (t = n.length - 1);
        n.push(g({
            title: "Fix stuttering (1.0001x)"
        }, null, [{
            signalAction: {
                signal: "POPUP_BACK"
            }
        }, {
            setClientSettingEndpoint: {
                settingDatas: [{
                    clientSettingEnum: {
                        item: "videoSpeed"
                    },
                    intValue: "1.0001"
                }]
            }
        }, {
            customAction: {
                action: "SET_PLAYER_SPEED",
                parameters: "1.0001"
            }
        }])), h("Playback Speed", n, t, "tt-speed")
    }

    function E(e, t) {
        for (var n in window._yttv)
            if (window._yttv[n] && window._yttv[n].instance && window._yttv[n].instance.resolveCommand) return window._yttv[n].instance.resolveCommand(e, t)
    }

    function T(e, t) {
        switch (e) {
            case "SETTINGS_UPDATE":
                w(!0, t);
                break;
            case "OPTIONS_SHOW":
                ! function(e, t) {
                    var o, i = [],
                        r = p("sponsorBlockManualSkips"),
                        a = n(e.options);
                    try {
                        for (a.s(); !(o = a.n()).done;) {
                            var l = o.value;
                            i.push(g({
                                title: l.name
                            }, {
                                icon: l.icon ? l.icon : "CHEVRON_DOWN",
                                secondaryIcon: r.includes(l.value) ? "CHECK_BOX" : "CHECK_BOX_OUTLINE_BLANK"
                            }, [{
                                setClientSettingEndpoint: {
                                    settingDatas: [{
                                        clientSettingEnum: {
                                            item: "sponsorBlockManualSkips"
                                        },
                                        arrayValue: l.value
                                    }]
                                }
                            }, {
                                customAction: {
                                    action: "OPTIONS_SHOW",
                                    parameters: {
                                        options: e.options,
                                        selectedIndex: e.options.indexOf(l),
                                        update: !0
                                    }
                                }
                            }]))
                        }
                    } catch (e) {
                        a.e(e)
                    } finally {
                        a.f()
                    }
                    h("TizenTube Settings", i, e.selectedIndex, "tt-settings-options", t)
                }(t, t.update);
                break;
            case "SKIP":
                var o = document.createEvent("Event");
                o.initEvent("keydown", !0, !0), o.keyCode = 27, o.which = 27, document.dispatchEvent(o), document.querySelector("video").currentTime = t.time;
                break;
            case "TT_SETTINGS_SHOW":
                w();
                break;
            case "TT_SPEED_SETTINGS_SHOW":
                k();
                break;
            case "UPDATE_REMIND_LATER":
                m("dontCheckUpdateUntil", t);
                break;
            case "UPDATE_DOWNLOAD":
                window.h5vcc.tizentube.InstallAppFromURL(t), v("TizenTube Update", "Downloading update, please wait...");
                break;
            case "SET_PLAYER_SPEED":
                var i = Number(t);
                document.querySelector("video").playbackRate = i
        }
    }
    var P = JSON.parse;
    for (var C in JSON.parse = function() {
            var e, t, o, i, r, a, l, s, c, u, d, m, f = P.apply(this, arguments);
            (f.adPlacements && p("enableAdBlock") && (f.adPlacements = []), f.playerAds && p("enableAdBlock") && (f.playerAds = !1), f.adSlots && p("enableAdBlock") && (f.adSlots = []), null != f && null !== (e = f.contents) && void 0 !== e && null !== (e = e.tvBrowseRenderer) && void 0 !== e && null !== (e = e.content) && void 0 !== e && null !== (e = e.tvSurfaceContentRenderer) && void 0 !== e && null !== (e = e.content) && void 0 !== e && null !== (e = e.sectionListRenderer) && void 0 !== e && e.contents && p("enableAdBlock") && (f.contents.tvBrowseRenderer.content.tvSurfaceContentRenderer.content.sectionListRenderer.contents = f.contents.tvBrowseRenderer.content.tvSurfaceContentRenderer.content.sectionListRenderer.contents.filter(e => !e.adSlotRenderer)), !Array.isArray(f) && null != f && f.entries && p("enableAdBlock")) && (f.entries = null === (c = f.entries) || void 0 === c ? void 0 : c.filter(e => {
                var t;
                return !(null != e && null !== (t = e.command) && void 0 !== t && null !== (t = t.reelWatchEndpoint) && void 0 !== t && null !== (t = t.adClientParams) && void 0 !== t && t.isAd)
            }));
            if (null != f && null !== (t = f.title) && void 0 !== t && t.runs && (u = f, m = function(e, t, n) {
                    var o = {
                        settingCategoryCollectionRenderer: {
                            items: t,
                            categoryId: "tizentube_category",
                            focused: !1,
                            trackingParams: "null"
                        }
                    };
                    return n && (o.settingCategoryCollectionRenderer.title = {
                        runs: [{
                            text: n
                        }]
                    }), o
                }(0, [{
                    settingActionRenderer: {
                        title: {
                            runs: [{
                                text: d = "TizenTube Settings"
                            }]
                        },
                        serviceEndpoint: {
                            customAction: {
                                action: "TT_SETTINGS_SHOW",
                                parameters: []
                            }
                        },
                        summary: {
                            runs: [{
                                text: "Open TizenTube Settings"
                            }]
                        },
                        trackingParams: "null",
                        actionLabel: {
                            runs: [{
                                text: d
                            }]
                        },
                        itemId: "tizentube_open_action",
                        thumbnail: {
                            thumbnails: [{
                                url: "https://www.gstatic.com/ytlr/img/parent_code.png"
                            }]
                        }
                    }
                }]), u.items.unshift(m)), null != f && null !== (o = f.contents) && void 0 !== o && null !== (o = o.tvBrowseRenderer) && void 0 !== o && null !== (o = o.content) && void 0 !== o && null !== (o = o.tvSurfaceContentRenderer) && void 0 !== o && null !== (o = o.content) && void 0 !== o && null !== (o = o.sectionListRenderer) && void 0 !== o && o.contents && _(f.contents.tvBrowseRenderer.content.tvSurfaceContentRenderer.content.sectionListRenderer.contents), null != f && null !== (i = f.contents) && void 0 !== i && null !== (i = i.sectionListRenderer) && void 0 !== i && i.contents && _(f.contents.sectionListRenderer.contents), null != f && null !== (r = f.continuationContents) && void 0 !== r && null !== (r = r.sectionListContinuation) && void 0 !== r && r.contents && _(f.continuationContents.sectionListContinuation.contents), null != f && null !== (a = f.continuationContents) && void 0 !== a && null !== (a = a.horizontalListContinuation) && void 0 !== a && a.items && (R(f.continuationContents.horizontalListContinuation.items), x(f.continuationContents.horizontalListContinuation.items), N(f.continuationContents.horizontalListContinuation.items)), !p("enableShorts") && null != f && null !== (l = f.contents) && void 0 !== l && null !== (l = l.tvBrowseRenderer) && void 0 !== l && null !== (l = l.content) && void 0 !== l && null !== (l = l.tvSurfaceContentRenderer) && void 0 !== l && l.content && (f.contents.tvBrowseRenderer.content.tvSurfaceContentRenderer.content.sectionListRenderer.contents = f.contents.tvBrowseRenderer.content.tvSurfaceContentRenderer.content.sectionListRenderer.contents.filter(e => {
                    var t;
                    return "TVHTML5_SHELF_RENDERER_TYPE_SHORTS" !== (null === (t = e.shelfRenderer) || void 0 === t ? void 0 : t.tvhtml5ShelfRendererType)
                })), p("sponsorBlockManualSkips").length > 0 && null != f && null !== (s = f.playerOverlays) && void 0 !== s && s.playerOverlayRenderer) {
                var v, h = p("sponsorBlockManualSkips"),
                    g = [];
                if (null !== (v = window) && void 0 !== v && null !== (v = v.sponsorblock) && void 0 !== v && v.segments) {
                    var b, w = n(window.sponsorblock.segments);
                    try {
                        for (w.s(); !(b = w.n()).done;) {
                            var S = b.value;
                            if (h.includes(S.category)) {
                                var k = y(`Skip ${S.category}`, "SKIP_NEXT", {
                                    clickTrackingParams: null,
                                    showEngagementPanelEndpoint: {
                                        customAction: {
                                            action: "SKIP",
                                            parameters: {
                                                time: S.segment[1]
                                            }
                                        }
                                    }
                                }, 1e3 * S.segment[0], 1e3 * S.segment[1] - 1e3 * S.segment[0]);
                                g.push(k)
                            }
                        }
                    } catch (e) {
                        w.e(e)
                    } finally {
                        w.f()
                    }
                    f.playerOverlays.playerOverlayRenderer.timelyActionRenderers = g
                }
            }
            return f
        }, window.JSON.parse = JSON.parse, window._yttv) window._yttv[C] && window._yttv[C].JSON && window._yttv[C].JSON.parse && (window._yttv[C].JSON.parse = JSON.parse);

    function _(e) {
        var t, o = n(e);
        try {
            for (o.s(); !(t = o.n()).done;) {
                var i = t.value;
                i.shelfRenderer && (R(i.shelfRenderer.content.horizontalListRenderer.items), x(i.shelfRenderer.content.horizontalListRenderer.items), N(i.shelfRenderer.content.horizontalListRenderer.items))
            }
        } catch (e) {
            o.e(e)
        } finally {
            o.f()
        }
    }

    function R(e) {
        var t, o = n(e);
        try {
            var i = function() {
                var n = t.value;
                if (n.adSlotRenderer) {
                    var o = e.indexOf(n);
                    return e.splice(o, 1), 1
                }
                if (p("enableDeArrow")) {
                    var i = n.tileRenderer.contentId;
                    fetch(`https://sponsor.ajay.app/api/branding?videoID=${i}`).then(e => e.json()).then(e => {
                        if (e.titles.length > 0) {
                            var t = e.titles.reduce((e, t) => e.votes > t.votes ? e : t);
                            n.tileRenderer.metadata.tileMetadataRenderer.title.simpleText = t.title
                        }
                        if (e.thumbnails.length > 0 && p("enableDeArrowThumbnails")) {
                            var o = e.thumbnails.reduce((e, t) => e.votes > t.votes ? e : t);
                            o.timestamp && (n.tileRenderer.header.tileHeaderRenderer.thumbnail.thumbnails = [{
                                url: `https://dearrow-thumb.ajay.app/api/v1/getThumbnail?videoID=${i}&time=${o.timestamp}`,
                                width: 1280,
                                height: 640
                            }])
                        }
                    })
                }
            };
            for (o.s(); !(t = o.n()).done;) i()
        } catch (e) {
            o.e(e)
        } finally {
            o.f()
        }
    }

    function x(e) {
        var t, o = n(e);
        try {
            for (o.s(); !(t = o.n()).done;) {
                var i = t.value;
                if ("TILE_STYLE_YTLR_DEFAULT" === i.tileRenderer.style && p("enableHqThumbnails")) {
                    var r = i.tileRenderer.contentId,
                        a = i.tileRenderer.header.tileHeaderRenderer.thumbnail.thumbnails[0].url.split("?")[1];
                    i.tileRenderer.header.tileHeaderRenderer.thumbnail.thumbnails = [{
                        url: `https://i.ytimg.com/vi/${r}/sddefault.jpg${a?`?${a}`:""}`,
                        width: 640,
                        height: 480
                    }]
                }
            }
        } catch (e) {
            o.e(e)
        } finally {
            o.f()
        }
    }

    function N(e) {
        if (p("enableLongPress")) {
            var t, o = n(e);
            try {
                for (o.s(); !(t = o.n()).done;) {
                    var i = t.value;
                    if ("TILE_STYLE_YTLR_DEFAULT" === i.tileRenderer.style && !i.tileRenderer.onLongPressCommand) {
                        var r = i.tileRenderer.metadata.tileMetadataRenderer.lines[0].lineRenderer.items[0].lineItemRenderer.text,
                            a = b({
                                videoId: i.tileRenderer.contentId,
                                thumbnails: i.tileRenderer.header.tileHeaderRenderer.thumbnail.thumbnails,
                                title: i.tileRenderer.metadata.tileMetadataRenderer.title.simpleText,
                                subtitle: r.runs ? r.runs[0].text : r.simpleText,
                                watchEndpointData: i.tileRenderer.onSelectCommand.watchEndpoint
                            });
                        i.tileRenderer.onLongPressCommand = a
                    }
                }
            } catch (e) {
                o.e(e)
            } finally {
                o.f()
            }
        }
    }
    var A = function e(t) {
            function n(e, t) {
                return e >>> t | e << 32 - t
            }
            for (var o, i, r = Math.pow, a = r(2, 32), l = "length", s = "", c = [], u = 8 * t[l], d = e.h = e.h || [], p = e.k = e.k || [], m = p[l], f = {}, v = 2; m < 64; v++)
                if (!f[v]) {
                    for (o = 0; o < 313; o += v) f[o] = v;
                    d[m] = r(v, .5) * a | 0, p[m++] = r(v, 1 / 3) * a | 0
                } for (t += ""; t[l] % 64 - 56;) t += "\0";
            for (o = 0; o < t[l]; o++) {
                if ((i = t.charCodeAt(o)) >> 8) return;
                c[o >> 2] |= i << (3 - o) % 4 * 8
            }
            for (c[c[l]] = u / a | 0, c[c[l]] = u, i = 0; i < c[l];) {
                var h = c.slice(i, i += 16),
                    g = d;
                for (d = d.slice(0, 8), o = 0; o < 64; o++) {
                    var y = h[o - 15],
                        b = h[o - 2],
                        w = d[0],
                        S = d[4],
                        k = d[7] + (n(S, 6) ^ n(S, 11) ^ n(S, 25)) + (S & d[5] ^ ~S & d[6]) + p[o] + (h[o] = o < 16 ? h[o] : h[o - 16] + (n(y, 7) ^ n(y, 18) ^ y >>> 3) + h[o - 7] + (n(b, 17) ^ n(b, 19) ^ b >>> 10) | 0);
                    (d = [k + ((n(w, 2) ^ n(w, 13) ^ n(w, 22)) + (w & d[1] ^ w & d[2] ^ d[1] & d[2])) | 0].concat(d))[4] = d[4] + k | 0
                }
                for (o = 0; o < 8; o++) d[o] = d[o] + g[o] | 0
            }
            for (o = 0; o < 8; o++)
                for (i = 3; i + 1; i--) {
                    var E = d[o] >> 8 * i & 255;
                    s += (E < 16 ? 0 : "") + E.toString(16)
                }
            return s
        },
        I = {
            sponsor: {
                color: "#00d400",
                opacity: "0.7",
                name: "sponsored segment"
            },
            intro: {
                color: "#00ffff",
                opacity: "0.7",
                name: "intro"
            },
            outro: {
                color: "#0202ed",
                opacity: "0.7",
                name: "outro"
            },
            interaction: {
                color: "#cc00ff",
                opacity: "0.7",
                name: "interaction reminder"
            },
            selfpromo: {
                color: "#ffff00",
                opacity: "0.7",
                name: "self-promotion"
            },
            preview: {
                color: "#008fd6",
                opacity: "0.7",
                name: "recap or preview"
            },
            filler: {
                color: "#7300FF",
                opacity: "0.9",
                name: "tangents"
            },
            music_offtopic: {
                color: "#ff9900",
                opacity: "0.7",
                name: "non-music part"
            }
        };
    class L {
        constructor(e) {
            o(this, "video", null), o(this, "active", !0), o(this, "attachVideoTimeout", null), o(this, "nextSkipTimeout", null), o(this, "sliderInterval", null), o(this, "observer", null), o(this, "scheduleSkipHandler", null), o(this, "durationChangeHandler", null), o(this, "segments", null), o(this, "skippableCategories", []), o(this, "manualSkippableCategories", []), this.videoID = e
        }
        init() {
            var e, n = this;
            return (e = i().m(function e() {
                var t, o, r, a, l;
                return i().w(function(e) {
                    for (;;) switch (e.n) {
                        case 0:
                            return t = A(n.videoID).substring(0, 4), o = ["sponsor", "intro", "outro", "interaction", "selfpromo", "preview", "filler", "music_offtopic"], e.n = 1, fetch(`https://sponsorblock.inf.re/api/skipSegments/${t}?categories=${encodeURIComponent(JSON.stringify(o))}`);
                        case 1:
                            return r = e.v, e.n = 2, r.json();
                        case 2:
                            if (a = e.v, l = a.find(e => e.videoID === n.videoID), console.info(n.videoID, "Got it:", l), l && l.segments && l.segments.length) {
                                e.n = 3;
                                break
                            }
                            return console.info(n.videoID, "No segments found."), e.a(2);
                        case 3:
                            n.segments = l.segments, n.manualSkippableCategories = p("sponsorBlockManualSkips"), n.skippableCategories = n.getSkippableCategories(), n.scheduleSkipHandler = () => n.scheduleSkip(), n.durationChangeHandler = () => n.buildOverlay(), n.attachVideo(), n.buildOverlay();
                        case 4:
                            return e.a(2)
                    }
                }, e)
            }), function() {
                var n = this,
                    o = arguments;
                return new Promise(function(i, r) {
                    var a = e.apply(n, o);

                    function l(e) {
                        t(a, i, r, l, s, "next", e)
                    }

                    function s(e) {
                        t(a, i, r, l, s, "throw", e)
                    }
                    l(void 0)
                })
            })()
        }
        getSkippableCategories() {
            var e = [];
            return p("enableSponsorBlockSponsor") && e.push("sponsor"), p("enableSponsorBlockIntro") && e.push("intro"), p("enableSponsorBlockOutro") && e.push("outro"), p("enableSponsorBlockInteraction") && e.push("interaction"), p("enableSponsorBlockSelfPromo") && e.push("selfpromo"), p("enableSponsorBlockPreview") && e.push("preview"), p("enableSponsorBlockFiller") && e.push("filler"), p("enableSponsorBlockMusicOfftopic") && e.push("music_offtopic"), e
        }
        attachVideo() {
            if (clearTimeout(this.attachVideoTimeout), this.attachVideoTimeout = null, this.video = document.querySelector("video"), !this.video) return console.info(this.videoID, "No video yet..."), void(this.attachVideoTimeout = setTimeout(() => this.attachVideo(), 100));
            console.info(this.videoID, "Video found, binding..."), this.video.addEventListener("play", this.scheduleSkipHandler), this.video.addEventListener("pause", this.scheduleSkipHandler), this.video.addEventListener("timeupdate", this.scheduleSkipHandler), this.video.addEventListener("durationchange", this.durationChangeHandler)
        }
        buildOverlay() {
            if (this.segmentsoverlay) console.info("Overlay already built");
            else if (this.video && this.video.duration) {
                var e = this.video.duration;
                this.segmentsoverlay = document.createElement("div"), this.segmentsoverlay.classList.add("ytLrProgressBarHost", "ytLrProgressBarFocused", "ytLrWatchDefaultProgressBar");
                var t = document.createElement("div");
                t.style.setProperty("background-color", "rgb(0, 0, 0, 0)"), t.style.setProperty("bottom", "auto", "important"), t.style.setProperty("height", "0.25rem", "important"), t.style.setProperty("overflow", "hidden", "important"), t.style.setProperty("position", "absolute", "important"), t.style.setProperty("top", "1.625rem", "important"), t.style.setProperty("width", "100%", "important"), this.segmentsoverlay.appendChild(t), this.segments.forEach(n => {
                    var o = a(n.segment, 2),
                        i = o[0],
                        r = o[1],
                        l = I[n.category] || {
                            color: "blue",
                            opacity: .7
                        },
                        s = `translateX(${i/e*100}%) scaleX(${(r-i)/e})`,
                        c = document.createElement("div");
                    c.style.setProperty("background", l.color, "important"), c.style.setProperty("opacity", l.opacity, "important"), c.style.setProperty("transform", s, "important"), c.style.setProperty("height", "100%"), c.style.setProperty("pointer-events", "none"), c.style.setProperty("position", "absolute"), c.style.setProperty("transform-origin", "left"), c.style.setProperty("width", "100%"), console.info("Generated element", c, "from", n, s), t.appendChild(c)
                }), this.observer = new MutationObserver(e => {
                    e.forEach(e => {
                        if (e.removedNodes) {
                            var t, o = n(e.removedNodes);
                            try {
                                for (o.s(); !(t = o.n()).done;) {
                                    t.value === this.segmentsoverlay && (console.info("bringing back segments overlay"), this.slider.appendChild(this.segmentsoverlay))
                                }
                            } catch (e) {
                                o.e(e)
                            } finally {
                                o.f()
                            }
                        }
                        "false" === document.querySelector("ytlr-progress-bar").getAttribute("hybridnavfocusable") ? this.segmentsoverlay.classList.remove("ytLrProgressBarFocused") : this.segmentsoverlay.classList.add("ytLrProgressBarFocused")
                    })
                }), this.sliderInterval = setInterval(() => {
                    this.slider = document.querySelector("ytlr-redux-connect-ytlr-progress-bar"), this.slider && (clearInterval(this.sliderInterval), this.sliderInterval = null, this.observer.observe(this.slider, {
                        childList: !0,
                        subtree: !0
                    }), this.slider.appendChild(this.segmentsoverlay))
                }, 500)
            } else console.info("No video duration yet")
        }
        scheduleSkip() {
            if (clearTimeout(this.nextSkipTimeout), this.nextSkipTimeout = null, this.active)
                if (this.video.paused) console.info(this.videoID, "Currently paused, ignoring...");
                else {
                    var e = this.segments.filter(e => e.segment[0] > this.video.currentTime - .3 && e.segment[1] > this.video.currentTime - .3);
                    if (e.sort((e, t) => e.segment[0] - t.segment[0]), e.length) {
                        var t = a(e, 1)[0],
                            n = a(t.segment, 2),
                            o = n[0],
                            i = n[1];
                        console.info(this.videoID, "Scheduling skip of", t, "in", o - this.video.currentTime), this.nextSkipTimeout = setTimeout(() => {
                            var e;
                            if (this.video.paused) console.info(this.videoID, "Currently paused, ignoring...");
                            else if (this.skippableCategories.includes(t.category)) {
                                var n = (null === (e = I[t.category]) || void 0 === e ? void 0 : e.name) || t.category;
                                console.info(this.videoID, "Skipping", t), this.manualSkippableCategories.includes(t.category) || (v("SponsorBlock", `Skipping ${n}`), this.video.currentTime = i + .1, this.scheduleSkip())
                            } else console.info(this.videoID, "Segment", t.category, "is not skippable, ignoring...")
                        }, 1e3 * (o - this.video.currentTime))
                    } else console.info(this.videoID, "No more segments")
                }
            else console.info(this.videoID, "No longer active, ignoring...")
        }
        destroy() {
            console.info(this.videoID, "Destroying"), this.active = !1, this.nextSkipTimeout && (clearTimeout(this.nextSkipTimeout), this.nextSkipTimeout = null), this.attachVideoTimeout && (clearTimeout(this.attachVideoTimeout), this.attachVideoTimeout = null), this.sliderInterval && (clearInterval(this.sliderInterval), this.sliderInterval = null), this.observer && (this.observer.disconnect(), this.observer = null), this.segmentsoverlay && (this.segmentsoverlay.remove(), this.segmentsoverlay = null), this.video && (this.video.removeEventListener("play", this.scheduleSkipHandler), this.video.removeEventListener("pause", this.scheduleSkipHandler), this.video.removeEventListener("timeupdate", this.scheduleSkipHandler), this.video.removeEventListener("durationchange", this.durationChangeHandler))
        }
    }
    window.sponsorblock = null, window.addEventListener("hashchange", () => {
            var e = new URL(location.hash.substring(1), location.href).search.replace("?v=", "").split("&")[0],
                t = e && (!window.sponsorblock || window.sponsorblock.videoID != e);
            if (console.info("hashchange", e, window.sponsorblock, window.sponsorblock ? window.sponsorblock.videoID : null, t), t) {
                if (window.sponsorblock) {
                    try {
                        window.sponsorblock.destroy()
                    } catch (e) {
                        console.warn("window.sponsorblock.destroy() failed!", e)
                    }
                    window.sponsorblock = null
                }
                p("enableSponsorBlock") ? (window.sponsorblock = new L(e), window.sponsorblock.init()) : console.info("SponsorBlock disabled, not loading")
            }
        }, !1),
        function() {
            if (!("navigate" in window)) {
                var e = {
                        37: "left",
                        38: "up",
                        39: "right",
                        40: "down"
                    },
                    t = null,
                    o = null,
                    i = {
                        element: null,
                        rect: null
                    },
                    r = null;
                window.navigate = s, window.Element.prototype.spatialNavigationSearch = m, window.Element.prototype.focusableAreas = b, window.Element.prototype.getSpatialNavigationContainer = g, window.CSS && CSS.registerProperty && ("" === window.getComputedStyle(document.documentElement).getPropertyValue("--spatial-navigation-contain") && CSS.registerProperty({
                    name: "--spatial-navigation-contain",
                    syntax: "auto | contain",
                    inherits: !1,
                    initialValue: "auto"
                }), "" === window.getComputedStyle(document.documentElement).getPropertyValue("--spatial-navigation-action") && CSS.registerProperty({
                    name: "--spatial-navigation-action",
                    syntax: "auto | focus | scroll",
                    inherits: !1,
                    initialValue: "auto"
                }), "" === window.getComputedStyle(document.documentElement).getPropertyValue("--spatial-navigation-function") && CSS.registerProperty({
                    name: "--spatial-navigation-function",
                    syntax: "normal | grid",
                    inherits: !1,
                    initialValue: "normal"
                })), K(!1), window.addEventListener("load", () => {
                    a()
                })
            }

            function a() {
                window.addEventListener("keydown", n => {
                    var i = parent && parent.__spatialNavigation__.keyMode || window.__spatialNavigation__.keyMode,
                        r = document.activeElement,
                        a = e[n.keyCode];
                    if (9 === n.keyCode && (o = null), !(!i || "NONE" === i || "SHIFTARROW" === i && !n.shiftKey || "ARROW" === i && n.shiftKey || n.defaultPrevented)) {
                        var l = {
                            left: !0,
                            up: !0,
                            right: !0,
                            down: !0
                        };
                        "INPUT" !== r.nodeName && "TEXTAREA" !== r.nodeName || (l = function(t) {
                            var n = ["email", "date", "month", "number", "time", "week"],
                                o = ["password", "text", "search", "tel", "url", null],
                                i = document.activeElement,
                                r = {
                                    left: !1,
                                    up: !1,
                                    right: !1,
                                    down: !1
                                },
                                a = e[t.keyCode];
                            if (void 0 === a) return r;
                            if (!n.includes(i.getAttribute("type")) || "up" !== a && "down" !== a)
                                if (o.includes(i.getAttribute("type")) || "TEXTAREA" === i.nodeName) {
                                    var l = i.selectionStart,
                                        s = i.selectionEnd;
                                    l === s && (0 === l && (r.left = !0, r.up = !0), s === i.value.length && (r.right = !0, r.down = !0))
                                } else r[a] = !0;
                            else r[a] = !0;
                            return r
                        }(n)), l[a] && (n.preventDefault(), t = new Map, s(a), t = null, o = null)
                    }
                }), document.addEventListener("mouseup", e => {
                    o = {
                        x: e.clientX,
                        y: e.clientY
                    }
                }), window.addEventListener("focusin", e => {
                    e.target !== window && (i.element = e.target, i.rect = e.target.getBoundingClientRect())
                })
            }

            function s(e) {
                var t = function() {
                        var e = document.activeElement;
                        if (!e || e === document.body && !document.querySelector(":focus")) {
                            if (i.element && e !== i.element) {
                                var t = window.getComputedStyle(i.element, null),
                                    n = ["hidden", "collapse"];
                                if (i.element.disabled || n.includes(t.getPropertyValue("visibility"))) return e = i.element
                            }
                            e = document.documentElement
                        }!i.element || 0 !== G(i.element).height && 0 !== G(i.element).width || (r = i.rect);
                        if (!I(e)) {
                            var o = y(e);
                            if (o && (o === window || "auto" === k(o))) return o
                        }
                        return e
                    }(),
                    n = t,
                    a = null;
                o && (null === (a = document.elementFromPoint(o.x, o.y)) && (a = document.body), L(a) && !P(a) ? o = null : n = P(a) ? a : a.getSpatialNavigationContainer()), n !== document && n !== document.documentElement || (n = document.body || document.documentElement);
                var l = null;
                if ((P(n) || "BODY" === n.nodeName) && "INPUT" !== n.nodeName) {
                    "IFRAME" === n.nodeName && (n = n.contentDocument.documentElement), l = n;
                    if (document.activeElement === t || document.activeElement === document.body && t === document.documentElement) {
                        if ("scroll" === k(n)) {
                            if (u(n, e)) return
                        } else if ("focus" === k(n)) {
                            if (c(n.spatialNavigationSearch(e, {
                                    container: n,
                                    candidates: d(n, {
                                        mode: "all"
                                    })
                                }), e)) return
                        } else if ("auto" === k(n) && (c(n.spatialNavigationSearch(e, {
                                container: n
                            }), e) || u(n, e))) return
                    } else l = l.getSpatialNavigationContainer()
                }
                var s = (l = n.getSpatialNavigationContainer()).parentElement ? l.getSpatialNavigationContainer() : null;
                if (s || window.location === window.parent.location || (s = window.parent.document.documentElement), "scroll" === k(l)) {
                    if (u(l, e)) return
                } else "focus" === k(l) ? E(n, l, s, e, "all") : "auto" === k(l) && E(n, l, s, e, "visible")
            }

            function c(e, t) {
                if (e) {
                    if (!w("beforefocus", e, null, t)) return !0;
                    var n = e.getSpatialNavigationContainer();
                    return n !== window && "focus" === k(n) ? e.focus() : e.focus({
                        preventScroll: !0
                    }), o = null, !0
                }
                return !1
            }

            function u(e, t) {
                return R(e, t) && !A(e, t) ? (T(e, t), !0) : !e.parentElement && !N(e, t) && (T(e.ownerDocument.documentElement, t), !0)
            }

            function d(e) {
                var t = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : {
                        mode: "visible"
                    },
                    o = [];
                if (e.childElementCount > 0) {
                    e.parentElement || (e = e.getElementsByTagName("body")[0] || document.body);
                    var i, r = n(e.children);
                    try {
                        for (r.s(); !(i = r.n()).done;) {
                            var a = i.value;
                            C(a) ? o.push(a) : L(a) ? (o.push(a), !P(a) && a.childElementCount && (o = o.concat(d(a, {
                                mode: "all"
                            })))) : a.childElementCount && (o = o.concat(d(a, {
                                mode: "all"
                            })))
                        }
                    } catch (e) {
                        r.e(e)
                    } finally {
                        r.f()
                    }
                }
                return "all" === t.mode ? o : o.filter(O)
            }

            function p(e, t, n, o) {
                var i = e;
                return o = o || i.getSpatialNavigationContainer(), f(i, n = !n || n.length <= 0 ? d(o) : n, t, o)
            }

            function m(e, t) {
                var n, i = this,
                    a = [],
                    l = [],
                    s = function(e) {
                        var t = e.getSpatialNavigationContainer(),
                            n = t.focusableAreas(),
                            o = [];
                        return n.forEach(t => {
                            e !== t && D(t, e) && o.push(t)
                        }), o
                    }(i);
                t || (t = {});
                var c = i.getSpatialNavigationContainer(),
                    u = d(c),
                    m = t.container || c;
                t.container && c.contains(t.container) && (u = u.concat(d(m)));
                var f = t.candidates && t.candidates.length > 0 ? t.candidates.filter(e => m.contains(e)) : u.filter(e => m.contains(e) && m !== e);
                if (f && f.length > 0) {
                    f.forEach(e => {
                        e !== i && (i.contains(e) && i !== e ? a : l).push(e)
                    });
                    var g = s.filter(e => !a.includes(e)),
                        y = f.filter(e => P(e) && D(i, e)).map(e => e.focusableAreas()).flat().filter(e => e !== i);
                    if (a = a.concat(g).filter(e => m.contains(e)), (l = l.concat(y).filter(e => m.contains(e))).length > 0 && (l = p(i, e, l, m)), r && (n = v(i, p(i, e, a, m), e)), a && a.length > 0 && "INPUT" !== i.nodeName && (n = function(e, t, n) {
                            return h(e, t, n, o ? W : z)
                        }(i, a, e)), (n = n || v(i, l, e)) && C(n)) {
                        var b = d(n, {
                                mode: "all"
                            }),
                            w = b.length > 0 ? i.spatialNavigationSearch(e, {
                                candidates: b,
                                container: n
                            }) : null;
                        w ? n = w : L(n) || (f.splice(f.indexOf(n), 1), n = f.length ? i.spatialNavigationSearch(e, {
                            candidates: f,
                            container: m
                        }) : null)
                    }
                    return n
                }
                return null
            }

            function f(e, t, n, o) {
                var i, a = e.getSpatialNavigationContainer();
                return void 0 === n ? t : (i = a.parentElement && o !== a && !O(e) ? G(a) : r || G(e), !P(e) && "BODY" !== e.nodeName || "INPUT" === e.nodeName ? t.filter(t => {
                    var r = G(t),
                        a = "IFRAME" === t.nodeName ? t.contentDocument.body : null;
                    return o.contains(t) && t !== e && a !== e && H(r, i, n) && !B(i, r)
                }) : t.filter(t => {
                    var r = G(t);
                    return o.contains(t) && (e.contains(t) && B(i, r) && t !== e || H(r, i, n))
                }))
            }

            function v(e, t, n) {
                var o, i, a = e.getSpatialNavigationContainer(),
                    l = getComputedStyle(a).getPropertyValue("--spatial-navigation-function"),
                    s = r || G(e);
                if ("grid" === l)(i = t.filter(e => V(s, G(e), n))).length > 0 && (t = i), o = Y;
                else o = q;
                return h(e, t, n, o)
            }

            function h(e, t, n, o) {
                var i = null;
                window.location === window.parent.location || "BODY" !== e.nodeName && "HTML" !== e.nodeName ? i = r || e.getBoundingClientRect() : ((i = window.frameElement.getBoundingClientRect()).x = 0, i.y = 0);
                var a = Number.POSITIVE_INFINITY,
                    l = [];
                if (t)
                    for (var s = 0; s < t.length; s++) {
                        var c = o(i, G(t[s]), n);
                        c < a ? (a = c, l = [t[s]]) : c === a && l.push(t[s])
                    }
                return 0 === l.length ? null : l.length > 1 && o === Y ? h(e, l, n, j) : l[0]
            }

            function g() {
                var e = this;
                do {
                    if (!e.parentElement) {
                        e = window.location !== window.parent.location ? window.parent.document.documentElement : window.document.documentElement;
                        break
                    }
                    e = e.parentElement
                } while (!P(e));
                return e
            }

            function y(e) {
                var t = e;
                do {
                    if (!t.parentElement) {
                        t = window.location !== window.parent.location ? window.parent.document.documentElement : window.document.documentElement;
                        break
                    }
                    t = t.parentElement
                } while (!_(t) || !O(t));
                return t !== document && t !== document.documentElement || (t = window), t
            }

            function b() {
                var e = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : {
                        mode: "visible"
                    },
                    t = this.parentElement ? this : document.body,
                    n = Array.prototype.filter.call(t.getElementsByTagName("*"), L);
                return "all" === e.mode ? n : n.filter(O)
            }

            function w(e, t, n, o) {
                if (["beforefocus", "notarget"].includes(e)) {
                    var i = new CustomEvent("nav" + e, {
                        bubbles: !0,
                        cancelable: !0,
                        detail: {
                            causedTarget: n,
                            dir: o
                        }
                    });
                    return t.dispatchEvent(i)
                }
            }

            function S(e, t) {
                return (e.style.getPropertyValue(`--${t}`) || "").trim()
            }

            function k(e) {
                return S(e, "spatial-navigation-action") || "auto"
            }

            function E(e, t, n, o, i) {
                for (var r = {
                        candidates: d(t, {
                            mode: i
                        }),
                        container: t
                    }; n;) {
                    if (c(e.spatialNavigationSearch(o, r), o)) return;
                    if ("visible" === i && u(t, o)) return;
                    if (!w("notarget", t, e, o)) return;
                    t === document || t === document.documentElement ? window.location !== window.parent.location && (t = (e = window.frameElement).ownerDocument.documentElement) : t = n, r = {
                        candidates: d(t, {
                            mode: i
                        }),
                        container: t
                    };
                    var a = t.getSpatialNavigationContainer();
                    n = a !== t ? a : null
                }
                r = {
                    candidates: d(t, {
                        mode: i
                    }),
                    container: t
                }, !n && t && c(e.spatialNavigationSearch(o, r), o) || w("notarget", r.container, e, o) && ("auto" !== k(t) || "visible" !== i || u(t, o))
            }

            function T(e, t) {
                var n = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : 0;
                if (e) switch (t) {
                    case "left":
                        e.scrollLeft -= 40 + n;
                        break;
                    case "right":
                        e.scrollLeft += 40 + n;
                        break;
                    case "up":
                        e.scrollTop -= 40 + n;
                        break;
                    case "down":
                        e.scrollTop += 40 + n
                }
            }

            function P(e) {
                return !e.parentElement || "IFRAME" === e.nodeName || _(e) || function(e) {
                    return "contain" === S(e, "spatial-navigation-contain")
                }(e)
            }

            function C(e) {
                return "delegable" === S(e, "spatial-navigation-contain")
            }

            function _(e) {
                var t = window.getComputedStyle(e, null),
                    n = t.getPropertyValue("overflow-x"),
                    o = t.getPropertyValue("overflow-y");
                return !!("visible" !== n && "clip" !== n && x(e, "left") || "visible" !== o && "clip" !== o && x(e, "down"))
            }

            function R(e, t) {
                if (e && "object" === l(e)) {
                    if (t && "string" == typeof t) {
                        if (x(e, t)) {
                            var n = window.getComputedStyle(e, null),
                                o = n.getPropertyValue("overflow-x"),
                                i = n.getPropertyValue("overflow-y");
                            switch (t) {
                                case "left":
                                case "right":
                                    return "visible" !== o && "clip" !== o && "hidden" !== o;
                                case "up":
                                case "down":
                                    return "visible" !== i && "clip" !== i && "hidden" !== i
                            }
                        }
                        return !1
                    }
                    return "HTML" === e.nodeName || "BODY" === e.nodeName || _(e) && x(e)
                }
            }

            function x(e, t) {
                if (e && "object" === l(e)) {
                    if (!t || "string" != typeof t) return e.scrollWidth > e.clientWidth || e.scrollHeight > e.clientHeight;
                    switch (t) {
                        case "left":
                        case "right":
                            return e.scrollWidth > e.clientWidth;
                        case "up":
                        case "down":
                            return e.scrollHeight > e.clientHeight
                    }
                    return !1
                }
            }

            function N(e, t) {
                var n = !1;
                switch (t) {
                    case "left":
                        n = 0 === e.scrollLeft;
                        break;
                    case "right":
                        n = e.scrollWidth - e.scrollLeft - e.clientWidth === 0;
                        break;
                    case "up":
                        n = 0 === e.scrollTop;
                        break;
                    case "down":
                        n = e.scrollHeight - e.scrollTop - e.clientHeight === 0
                }
                return n
            }

            function A(e, t) {
                if (R(e, t)) {
                    var n = e.scrollTop,
                        o = e.scrollLeft,
                        i = e.scrollHeight - e.clientHeight,
                        r = e.scrollWidth - e.clientWidth;
                    switch (t) {
                        case "left":
                            return 0 === o;
                        case "right":
                            return Math.abs(o - r) <= 1;
                        case "up":
                            return 0 === n;
                        case "down":
                            return Math.abs(n - i) <= 1
                    }
                }
                return !1
            }

            function I(e) {
                var t = e.getBoundingClientRect(),
                    n = y(e),
                    o = null;
                return !(!B(o = n !== window ? G(n) : new DOMRect(0, 0, window.innerWidth, window.innerHeight), t) || !B(o, t))
            }

            function L(e) {
                return !(e.tabIndex < 0 || function(e) {
                    return "A" === e.tagName && null === e.getAttribute("href") && null === e.getAttribute("tabIndex")
                }(e) || function(e) {
                    return !!["BUTTON", "INPUT", "SELECT", "TEXTAREA", "OPTGROUP", "OPTION", "FIELDSET"].includes(e.tagName) && e.disabled
                }(e) || function(e) {
                    return e.inert && !e.ownerDocument.documentElement.inert
                }(e) || ! function(e) {
                    return !!M(e.parentElement) && !(!M(e) || "0" === e.style.opacity || "0px" === window.getComputedStyle(e).height || "0px" === window.getComputedStyle(e).width)
                }(e)) && (!!(!e.parentElement || R(e) && x(e) || e.tabIndex >= 0) || void 0)
            }

            function O(e) {
                return !e.parentElement || M(e) && function(e) {
                    var t = G(e);
                    if ("IFRAME" !== e.nodeName && (t.top < 0 || t.left < 0 || t.top > e.ownerDocument.documentElement.clientHeight || t.left > e.ownerDocument.documentElement.clientWidth)) return !1;
                    var n = parseInt(e.offsetWidth) / 10,
                        o = parseInt(e.offsetHeight) / 10;
                    n = isNaN(n) ? 1 : n, o = isNaN(o) ? 1 : o;
                    var i = {
                        middle: [(t.left + t.right) / 2, (t.top + t.bottom) / 2],
                        leftTop: [t.left + n, t.top + o],
                        rightBottom: [t.right - n, t.bottom - o]
                    };
                    for (var r in i) {
                        var a = e.ownerDocument.elementFromPoint(...i[r]);
                        if (e === a || e.contains(a)) return !0
                    }
                    return !1
                }(e)
            }

            function D(e, t) {
                var n = G(e),
                    o = G(t || e.getSpatialNavigationContainer());
                return !(n.left < o.left || n.right > o.right || n.top < o.top || n.bottom > o.bottom)
            }

            function M(e) {
                var t = window.getComputedStyle(e, null),
                    n = t.getPropertyValue("visibility");
                return "none" !== t.getPropertyValue("display") && !["hidden", "collapse"].includes(n)
            }

            function B(e, t) {
                var n = e.left <= t.right && e.right >= t.right,
                    o = e.left <= t.left && e.right >= t.left,
                    i = e.top <= t.top && e.bottom >= t.top,
                    r = e.top <= t.bottom && e.bottom >= t.bottom;
                return (n || o) && (i || r)
            }

            function H(e, t, n) {
                switch (n) {
                    case "left":
                        return F(t, e);
                    case "right":
                        return F(e, t);
                    case "up":
                        return U(t, e);
                    case "down":
                        return U(e, t);
                    default:
                        return !1
                }
            }

            function F(e, t) {
                return e.left >= t.right || e.left >= t.left && e.right > t.right && e.bottom > t.top && e.top < t.bottom
            }

            function U(e, t) {
                return e.top >= t.bottom || e.top >= t.top && e.bottom > t.bottom && e.left < t.right && e.right > t.left
            }

            function V(e, t, n) {
                switch (n) {
                    case "left":
                    case "right":
                        return e.bottom > t.top && e.top < t.bottom;
                    case "up":
                    case "down":
                        return e.right > t.left && e.left < t.right;
                    default:
                        return !1
                }
            }

            function W(e, t, n) {
                var i = $(n, o, t),
                    r = Math.abs(i.entryPoint.x - i.exitPoint.x),
                    a = Math.abs(i.entryPoint.y - i.exitPoint.y);
                return Math.sqrt(Math.pow(r, 2) + Math.pow(a, 2))
            }

            function z(e, t, n) {
                var o = {
                    left: "right",
                    right: "left",
                    up: "bottom",
                    down: "top"
                } [n];
                return Math.abs(e[o] - t[o])
            }

            function q(e, t, n) {
                var o, i, r = 0,
                    a = 0,
                    l = $(n, e, t),
                    s = Math.abs(l.entryPoint.x - l.exitPoint.x),
                    c = Math.abs(l.entryPoint.y - l.exitPoint.y),
                    u = Math.sqrt(Math.pow(s, 2) + Math.pow(c, 2)),
                    d = function(e, t) {
                        var n = {
                                width: 0,
                                height: 0,
                                area: 0
                            },
                            o = [Math.max(e.left, t.left), Math.max(e.top, t.top)],
                            i = [Math.min(e.right, t.right), Math.min(e.bottom, t.bottom)];
                        n.width = Math.abs(o[0] - i[0]), n.height = Math.abs(o[1] - i[1]), o[0] >= i[0] || o[1] >= i[1] || (n.area = Math.sqrt(n.width * n.height));
                        return n
                    }(e, t),
                    p = d.area;
                switch (n) {
                    case "left":
                    case "right":
                        V(e, t, n) ? a = Math.min(d.height / e.height, 1) : r = e.height / 2, o = 30 * (c + r), i = 5 * a;
                        break;
                    case "up":
                    case "down":
                        V(e, t, n) ? a = Math.min(d.width / e.width, 1) : r = e.width / 2, o = 2 * (s + r), i = 5 * a;
                        break;
                    default:
                        o = 0, i = 0
                }
                return u + o - i - p
            }

            function j(e, t, n) {
                var o = $(n, e, t),
                    i = Math.abs(o.entryPoint.x - o.exitPoint.x),
                    r = Math.abs(o.entryPoint.y - o.exitPoint.y);
                return Math.sqrt(Math.pow(i, 2) + Math.pow(r, 2))
            }

            function Y(e, t, n) {
                var o = $(n, e, t);
                return "left" === n || "right" === n ? Math.abs(o.entryPoint.x - o.exitPoint.x) : Math.abs(o.entryPoint.y - o.exitPoint.y)
            }

            function $() {
                var e = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : "down",
                    t = arguments.length > 1 ? arguments[1] : void 0,
                    n = arguments.length > 2 ? arguments[2] : void 0,
                    i = {
                        entryPoint: {
                            x: 0,
                            y: 0
                        },
                        exitPoint: {
                            x: 0,
                            y: 0
                        }
                    };
                if (o) {
                    switch (i.exitPoint = t, e) {
                        case "left":
                            i.entryPoint.x = n.right;
                            break;
                        case "up":
                            i.entryPoint.y = n.bottom;
                            break;
                        case "right":
                            i.entryPoint.x = n.left;
                            break;
                        case "down":
                            i.entryPoint.y = n.top
                    }
                    switch (e) {
                        case "left":
                        case "right":
                            o.y <= n.top ? i.entryPoint.y = n.top : o.y < n.bottom ? i.entryPoint.y = o.y : i.entryPoint.y = n.bottom;
                            break;
                        case "up":
                        case "down":
                            o.x <= n.left ? i.entryPoint.x = n.left : o.x < n.right ? i.entryPoint.x = o.x : i.entryPoint.x = n.right
                    }
                } else {
                    switch (e) {
                        case "left":
                            i.exitPoint.x = t.left, i.entryPoint.x = n.right < t.left ? n.right : t.left;
                            break;
                        case "up":
                            i.exitPoint.y = t.top, i.entryPoint.y = n.bottom < t.top ? n.bottom : t.top;
                            break;
                        case "right":
                            i.exitPoint.x = t.right, i.entryPoint.x = n.left > t.right ? n.left : t.right;
                            break;
                        case "down":
                            i.exitPoint.y = t.bottom, i.entryPoint.y = n.top > t.bottom ? n.top : t.bottom
                    }
                    switch (e) {
                        case "left":
                        case "right":
                            U(t, n) ? (i.exitPoint.y = t.top, i.entryPoint.y = n.bottom < t.top ? n.bottom : t.top) : U(n, t) ? (i.exitPoint.y = t.bottom, i.entryPoint.y = n.top > t.bottom ? n.top : t.bottom) : (i.exitPoint.y = Math.max(t.top, n.top), i.entryPoint.y = i.exitPoint.y);
                            break;
                        case "up":
                        case "down":
                            F(t, n) ? (i.exitPoint.x = t.left, i.entryPoint.x = n.right < t.left ? n.right : t.left) : F(n, t) ? (i.exitPoint.x = t.right, i.entryPoint.x = n.left > t.right ? n.left : t.right) : (i.exitPoint.x = Math.max(t.left, n.left), i.entryPoint.x = i.exitPoint.x)
                    }
                }
                return i
            }

            function G(e) {
                var n = t && t.get(e);
                if (!n) {
                    var o = e.getBoundingClientRect();
                    n = {
                        top: Number(o.top.toFixed(2)),
                        right: Number(o.right.toFixed(2)),
                        bottom: Number(o.bottom.toFixed(2)),
                        left: Number(o.left.toFixed(2)),
                        width: Number(o.width.toFixed(2)),
                        height: Number(o.height.toFixed(2))
                    }, t && t.set(e, n)
                }
                return n
            }

            function K(e) {
                var t = window.__spatialNavigation__ && window.__spatialNavigation__.keyMode;
                window.__spatialNavigation__ = !1 === e ? J() : Object.assign(J(), function() {
                    function e(e, t) {
                        return R(e, t) && !A(e, t) || !e.parentElement && !N(e, t)
                    }

                    function t(t, n, o, i) {
                        var r = n,
                            a = null;
                        if (r !== document && r !== document.documentElement || (r = document.body || document.documentElement), (P(r) || "BODY" === r.nodeName) && "INPUT" !== r.nodeName) {
                            "IFRAME" === r.nodeName && (r = r.contentDocument.body);
                            var l = d(r, i);
                            if (Array.isArray(l) && l.length > 0) return t ? p(r, o, l) : r.spatialNavigationSearch(o, {
                                candidates: l
                            });
                            if (e(r, o)) return t ? [] : r
                        }
                        var s = r.getSpatialNavigationContainer(),
                            c = s.parentElement ? s.getSpatialNavigationContainer() : null;
                        for (c || window.location === window.parent.location || (c = window.parent.document.documentElement); c;) {
                            var u = f(r, d(s, i), o, s);
                            if (Array.isArray(u) && u.length > 0) {
                                if (a = r.spatialNavigationSearch(o, {
                                        candidates: u,
                                        container: s
                                    })) return t ? u : a
                            } else {
                                if (e(s, o)) return t ? [] : r;
                                if (s === document || s === document.documentElement) {
                                    if (s = window.document.documentElement, window.location !== window.parent.location) {
                                        if (r = window.frameElement, !(s = window.parent.document.documentElement).parentElement) {
                                            c = null;
                                            break
                                        }
                                        c = s.getSpatialNavigationContainer()
                                    }
                                } else {
                                    if (L(s) && (r = s), !(s = c).parentElement) {
                                        c = null;
                                        break
                                    }
                                    c = s.getSpatialNavigationContainer()
                                }
                            }
                        }
                        if (!c && s) {
                            var m = f(r, d(s, i), o, s);
                            if (Array.isArray(m) && m.length > 0 && (a = r.spatialNavigationSearch(o, {
                                    candidates: m,
                                    container: s
                                }))) return t ? m : a
                        }
                        if (e(s, o)) return r
                    }
                    return {
                        isContainer: P,
                        isScrollContainer: _,
                        isVisibleInScroller: I,
                        findCandidates: t.bind(null, !0),
                        findNextTarget: t.bind(null, !1),
                        getDistanceFromTarget: (e, t, n) => (P(e) || "BODY" === e.nodeName) && "INPUT" !== e.nodeName && d(e).includes(t) ? z(G(e), G(t), n) : q(G(e), G(t), n)
                    }
                }()), window.__spatialNavigation__.keyMode = t, Object.seal(window.__spatialNavigation__)
            }

            function J() {
                return {
                    enableExperimentalAPIs: K,
                    get keyMode() {
                        return this._keymode ? this._keymode : "ARROW"
                    },
                    set keyMode(e) {
                        this._keymode = ["SHIFTARROW", "ARROW", "NONE"].includes(e) ? e : "ARROW"
                    },
                    setStartingPoint: function(e, t) {
                        o = e && t ? {
                            x: e,
                            y: t
                        } : null
                    }
                }
            }
        }();
    var O = ".ytaf-ui-container {\r\n  position: absolute;\r\n  top: 10%;\r\n  left: 10%;\r\n  right: 10%;\r\n  bottom: 10%;\r\n\r\n  background: rgba(0, 0, 0, 0.8);\r\n  color: white;\r\n  border-radius: 20px;\r\n  padding: 20px;\r\n  font-size: 1.5rem;\r\n  z-index: 1000;\r\n}\r\n\r\n.ytaf-ui-container :focus {\r\n  outline: 4px red solid;\r\n}\r\n\r\n.ytaf-ui-container h1 {\r\n  margin: 0;\r\n  margin-bottom: 0.5em;\r\n  text-align: center;\r\n}\r\n\r\n.ytaf-ui-container input[type='checkbox'] {\r\n  width: 1.4rem;\r\n  height: 1.4rem;\r\n}\r\n\r\n.ytaf-ui-container input[type='radio'] {\r\n  width: 1.4rem;\r\n  height: 1.4rem;\r\n}\r\n\r\n.ytaf-ui-container label {\r\n  display: block;\r\n  font-size: 1.4rem;\r\n}\r\n\r\n.ytaf-notification-container {\r\n  position: absolute;\r\n  right: 10px;\r\n  bottom: 10px;\r\n  font-size: 16pt;\r\n  z-index: 1200;\r\n}\r\n\r\n.ytaf-notification-container .message {\r\n  background: rgba(0, 0, 0, 0.7);\r\n  color: white;\r\n  padding: 1em;\r\n  margin: 0.5em;\r\n  transition: all 0.3s ease-in-out;\r\n  opacity: 1;\r\n  line-height: 1;\r\n  border-right: 10px solid rgba(50, 255, 50, 0.3);\r\n  display: inline-block;\r\n  float: right;\r\n}\r\n\r\n.ytaf-notification-container .message-hidden {\r\n  opacity: 0;\r\n  margin: 0 0.5em;\r\n  padding: 0 1em;\r\n  line-height: 0;\r\n}\r\n\r\n/* Fixes transparency effect for the video player */\r\n\r\n.ytLrWatchDefaultShadow {\r\n  background-image: linear-gradient(to bottom, rgba(0, 0, 0, 0) 0, rgba(0, 0, 0, 0.8) 90%) !important;\r\n  background-color: rgba(0, 0, 0, 0.3) !important;\r\n  display: block !important;\r\n  height: 100% !important;\r\n  pointer-events: none !important;\r\n  position: absolute !important;\r\n  width: 100% !important;\r\n}\r\n\r\n/* Fixes shorts having a black background */\r\n\r\n.ytLrTileHeaderRendererShorts {\r\n  background-image: none !important;\r\n}\r\n\r\n/* Multiline support for strings in the UI */\r\n\r\n.ytLrOverlayPanelHeaderRendererSubtitle {\r\n  white-space: pre-wrap !important;\r\n}\r\n\r\n/* Fixes SponsorBlock segments overlapping with the playhead */\r\n\r\n.ytLrProgressBarPlayhead {\r\n  z-index: 1 !important;\r\n}\r\n\r\n.ytLrProgressBarPlayed {\r\n  z-index: 1 !important;\r\n}",
        D = document.createElement("style"),
        M = "";

    function B() {
        M = `\n    ytlr-guide-response yt-focus-container {\n        background-color: ${p("focusContainerColor")};\n    }\n\n    #container {\n        background-color: ${p("routeColor")} !important;\n    }\n`;
        var e = document.querySelector("style[nonce]");
        e ? e.textContent += M : D.textContent = M
    }
    document.head.appendChild(D), B();
    var H = setInterval(() => {
        document.querySelector("video") && (! function() {
            var e = document.querySelector("style[nonce]");
            if (e) e.textContent += O;
            else {
                var t = document.createElement("style");
                t.textContent = O, document.head.appendChild(t)
            }
            if (p("enableFixedUI")) try {
                window.tectonicConfig.featureSwitches.isLimitedMemory = !1, window.tectonicConfig.clientData.legacyApplicationQuality = "full-animation", window.tectonicConfig.featureSwitches.enableAnimations = !0, window.tectonicConfig.featureSwitches.enableOnScrollLinearAnimation = !0, window.tectonicConfig.featureSwitches.enableListAnimations = !0
            } catch (e) {}
            window.__spatialNavigation__.keyMode = "NONE";
            var n = {
                    37: "left",
                    38: "up",
                    39: "right",
                    40: "down"
                },
                o = document.createElement("div");
            o.classList.add("ytaf-ui-container"), o.style.display = "none", o.setAttribute("tabindex", 0), o.addEventListener("focus", () => console.info("uiContainer focused!"), !0), o.addEventListener("blur", () => console.info("uiContainer blured!"), !0), o.addEventListener("keydown", e => {
                if (console.info("uiContainer key event:", e.type, e.keyCode, e), 404 !== e.keyCode && 172 !== e.keyCode) {
                    var t;
                    if (e.keyCode in n) navigate(n[e.keyCode]);
                    else {
                        if (13 === e.keyCode || 32 === e.keyCode) {
                            console.log("OK button pressed");
                            var i = document.querySelector(":focus");
                            return "checkbox" === i.type && (i.checked = !i.checked, i.dispatchEvent(new Event("change"))), e.preventDefault(), void e.stopPropagation()
                        }
                        if (27 === e.keyCode && "text" !== document.querySelector(":focus").type) o.style.display = "none", o.blur();
                        else if ("text" === document.querySelector(":focus").type && 27 === e.keyCode) {
                            var r = document.querySelector(":focus");
                            r.value = r.value.slice(0, -1)
                        }
                    }
                    "Enter" !== e.key && "Enter" !== (null === (t = e.Uc) || void 0 === t ? void 0 : t.key) || "text" === document.querySelector(":focus").type && document.querySelector(":focus").dispatchEvent(new Event("change"))
                }
            }, !0), o.innerHTML = '\n<h1>TizenTube Theme Configuration</h1>\n<label for="__barColor">Navigation Bar Color: <input type="text" id="__barColor"/></label>\n<label for="__routeColor">Main Content Color: <input type="text" id="__routeColor"/></label>\n<div><small>Sponsor segments skipping - https://sponsor.ajay.app</small></div>\n', document.querySelector("body").appendChild(o), o.querySelector("#__barColor").value = p("focusContainerColor"), o.querySelector("#__barColor").addEventListener("change", e => {
                m("focusContainerColor", e.target.value), B()
            }), o.querySelector("#__routeColor").value = p("routeColor"), o.querySelector("#__routeColor").addEventListener("change", e => {
                m("routeColor", e.target.value), B()
            });
            var i = e => (console.info("Key event:", e.type, e.keyCode, e.keyCode, e.defaultPrevented), 403 == e.keyCode ? (console.info("Taking over!"), e.preventDefault(), e.stopPropagation(), "keydown" === e.type && ("none" === o.style.display ? (console.info("Showing and focusing!"), o.style.display = "block", o.focus()) : (console.info("Hiding!"), o.style.display = "none", o.blur())), !1) : (404 == e.keyCode && "keydown" === e.type && w(), !0));
            if (document.addEventListener("keydown", i, !0), document.addEventListener("keypress", i, !0), document.addEventListener("keyup", i, !0), setTimeout(() => {
                    v("Welcome to TizenTube", "Go to settings and scroll down to TizenTube category to open TizenTube Settings, open playback settings, click on Speed to open Video Speed Settings and press [RED] to open TizenTube Theme Settings.")
                }, 2e3), p("enableFixedUI")) try {
                new MutationObserver((e, t) => {
                    var n = document.body;
                    n.classList.contains("app-quality-root") && n.classList.remove("app-quality-root")
                }).observe(document.body, {
                    attributes: !0,
                    childList: !1,
                    subtree: !1
                })
            } catch (e) {}
        }(), function() {
            var e = function() {
                if (window._yttv[t] && window._yttv[t].instance && window._yttv[t].instance.resolveCommand) {
                    var e = window._yttv[t].instance.resolveCommand;
                    window._yttv[t].instance.resolveCommand = function(t, o) {
                        var i, r, a;
                        if (t.setClientSettingEndpoint) {
                            var l, s = n(t.setClientSettingEndpoint.settingDatas);
                            try {
                                for (s.s(); !(l = s.n()).done;) {
                                    var c = l.value;
                                    if (c.clientSettingEnum.item.includes("_")) {
                                        if ("I18N_LANGUAGE" === c.clientSettingEnum.item) {
                                            var u = c.stringValue,
                                                d = new Date;
                                            return d.setFullYear(d.getFullYear() + 10), document.cookie = `PREF=hl=${u}; expires=${d.toUTCString()};`, E({
                                                signalAction: {
                                                    signal: "RELOAD_PAGE"
                                                }
                                            }), !0
                                        }
                                    } else {
                                        var f, v = n(t.setClientSettingEndpoint.settingDatas);
                                        try {
                                            for (v.s(); !(f = v.n()).done;) {
                                                var h = f.value,
                                                    g = Object.keys(h).find(e => e.includes("Value")),
                                                    y = "intValue" === g ? Number(h[g]) : h[g];
                                                if ("arrayValue" === g) {
                                                    var b = p(h.clientSettingEnum.item);
                                                    b.includes(y) ? b.splice(b.indexOf(y), 1) : b.push(y), m(h.clientSettingEnum.item, b)
                                                } else m(h.clientSettingEnum.item, y)
                                            }
                                        } catch (e) {
                                            v.e(e)
                                        } finally {
                                            v.f()
                                        }
                                    }
                                }
                            } catch (e) {
                                s.e(e)
                            } finally {
                                s.f()
                            }
                        } else {
                            if (t.customAction) return T(t.customAction.action, t.customAction.parameters), !0;
                            if (null != t && null !== (i = t.signalAction) && void 0 !== i && i.customAction) return T(t.signalAction.customAction.action, t.signalAction.customAction.parameters), !0;
                            if (null != t && null !== (r = t.showEngagementPanelEndpoint) && void 0 !== r && r.customAction) return T(t.showEngagementPanelEndpoint.customAction.action, t.showEngagementPanelEndpoint.customAction.parameters), !0;
                            if ("playback-settings" === (null == t || null === (a = t.openPopupAction) || void 0 === a ? void 0 : a.uniqueId)) {
                                var w, S = n(t.openPopupAction.popup.overlaySectionRenderer.overlay.overlayTwoPanelRenderer.actionPanel.overlayPanelRenderer.content.overlayPanelItemListRenderer.items);
                                try {
                                    for (S.s(); !(w = S.n()).done;) {
                                        var k, P = w.value;
                                        "SLOW_MOTION_VIDEO" === (null == P || null === (k = P.compactLinkRenderer) || void 0 === k || null === (k = k.icon) || void 0 === k ? void 0 : k.iconType) && (P.compactLinkRenderer.subtitle && (P.compactLinkRenderer.subtitle.simpleText = "with TizenTube"), P.compactLinkRenderer.serviceEndpoint = {
                                            clickTrackingParams: "null",
                                            signalAction: {
                                                customAction: {
                                                    action: "TT_SPEED_SETTINGS_SHOW",
                                                    parameters: []
                                                }
                                            }
                                        })
                                    }
                                } catch (e) {
                                    S.e(e)
                                } finally {
                                    S.f()
                                }
                            }
                        }
                        return e.call(this, t, o)
                    }
                }
            };
            for (var t in window._yttv) e()
        }(), clearInterval(H))
    }, 250);

    function F(e) {
        var t = JSON.parse(localStorage["yt.leanback.default::recurring_actions"]),
            n = new Date;
        if (e) {
            var o, i;
            if (n.getTime() - (null === (o = t.data.data["startup-screen-account-selector-with-guest"]) || void 0 === o ? void 0 : o.lastFired) > 0 && n.getTime() - (null === (i = t.data.data["startup-screen-account-selector-with-guest"]) || void 0 === i ? void 0 : i.lastFired) < 72e5) return;
            t.data.data["startup-screen-account-selector-with-guest"] && (t.data.data["startup-screen-account-selector-with-guest"].lastFired = n.getTime()), t.data.data.whos_watching_fullscreen_zero_accounts.lastFired = n.getTime(), t.data.data["startup-screen-signed-out-welcome-back"] && (t.data.data["startup-screen-signed-out-welcome-back"].lastFired = n.getTime()), localStorage["yt.leanback.default::recurring_actions"] = JSON.stringify(t)
        } else n.setDate(n.getDate() + 7), t.data.data["startup-screen-account-selector-with-guest"] && (t.data.data["startup-screen-account-selector-with-guest"].lastFired = n.getTime()), t.data.data.whos_watching_fullscreen_zero_accounts.lastFired = n.getTime(), t.data.data["startup-screen-signed-out-welcome-back"] && (t.data.data["startup-screen-signed-out-welcome-back"].lastFired = n.getTime()), localStorage["yt.leanback.default::recurring_actions"] = JSON.stringify(t)
    }
    if (f.addEventListener("configChange", e => {
            var t = e.detail,
                n = t.key,
                o = t.value;
            "enableWhoIsWatchingMenu" === n && F(o)
        }), F(p("enableWhoIsWatchingMenu")), window.h5vcc && window.h5vcc.tizentube) {
        var U = window.h5vcc.tizentube.GetVersion();
        var V = Math.floor(Date.now() / 1e3);

        function z() {
            fetch("https://api.github.com/repos/reisxd/TizenTubeCobalt/releases/latest").then(e => {
                if (!e.ok) throw new Error("Network response was not ok");
                return e.json()
            }).then(e => {
                var t = e.tag_name.replace("v", ""),
                    n = new Date(e.published_at).getTime() / 1e3;
                t !== U ? (console.info(`New version available: ${t} (current: ${U})`), h({
                    title: "Update Available",
                    subtitle: `A new version of TizenTube Cobalt is available: ${t}\nCurrent version: ${U}\nRelease Date: ${new Date(1e3*n).toLocaleString()}\nRelease Notes:\n${e.body}`
                }, [g({
                    title: "Update Now",
                    subtitle: "Click to download the latest version."
                }, {
                    icon: "DOWN_ARROW"
                }, [{
                    customAction: {
                        action: "UPDATE_DOWNLOAD",
                        parameters: e.assets[0].browser_download_url
                    }
                }, {
                    signalAction: {
                        signal: "POPUP_BACK"
                    }
                }]), g({
                    title: "Remind Me Later",
                    subtitle: "Check for updates later."
                }, {
                    icon: "SEARCH_HISTORY"
                }, [{
                    customAction: {
                        action: "UPDATE_REMIND_LATER",
                        parameters: V + 86400
                    }
                }, {
                    signalAction: {
                        signal: "POPUP_BACK"
                    }
                }])], 0, "tt-update-modal")) : console.info("You are using the latest version of TizenTube.")
            }).catch(e => {
                console.error("Error fetching the latest release:", e), v("TizenTube Update Check Failed", "Could not check for updates.", null)
            })
        }
        p("dontCheckUpdateUntil") > V ? console.info("Skipping update check until", new Date(1e3 * p("dontCheckUpdateUntil")).toLocaleString()) : z()
    }
}();
v("Hello World!")
