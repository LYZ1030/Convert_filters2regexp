const normalizeRegexSource = function(s) {
    try {
        const re = new RegExp(s);
        return re.source;
    } catch (ex) {
        normalizeRegexSource.message = ex.toString();
    }
    return '';
};
/******************************************************************************/
/******************************************************************************/

const FilterParser = function() {
    this.cantWebsocket = vAPI.cantWebsocket;
    this.reBadDomainOptChars = /[*+?^${}()[\]\\]/;
    this.reHostnameRule1 = /^[0-9a-z][0-9a-z.-]*[0-9a-z]$/i;
    this.reHostnameRule2 = /^[0-9a-z][0-9a-z.-]*[0-9a-z]\^?$/i;
    this.reCleanupHostnameRule2 = /\^$/g;
    this.reCanTrimCarets1 = /^[^*]*$/;
    this.reCanTrimCarets2 = /^\^?[^^]+[^^][^^]+\^?$/;
    this.reHasUppercase = /[A-Z]/;
    this.reIsolateHostname = /^(\*?\.)?([^\x00-\x24\x26-\x2C\x2F\x3A-\x5E\x60\x7B-\x7F]+)(.*)/;
    this.reHasUnicode = /[^\x00-\x7F]/;
    this.reWebsocketAny = /^ws[s*]?(?::\/?\/?)?\*?$/;
    this.reBadCSP = /(?:^|;)\s*report-(?:to|uri)\b/;
    this.domainOpt = '';
    this.noTokenHash = µb.urlTokenizer.tokenHashFromString('*');
    this.unsupportedTypeBit = this.bitFromType('unsupported');
    // All network request types to bitmap
    //   bring origin to 0 (from 4 -- see typeNameToTypeValue)
    //   left-shift 1 by the above-calculated value
    //   subtract 1 to set all type bits
    this.allNetRequestTypeBits = (1 << (otherTypeBitValue >>> 4)) - 1;
    this.reset();
};

/******************************************************************************/

// https://github.com/gorhill/uBlock/issues/1493
//   Transpose `ping` into `other` for now.

FilterParser.prototype.toNormalizedType = {
            'beacon': 'other',
               'css': 'stylesheet',
              'data': 'data',
          'document': 'main_frame',
          'elemhide': 'generichide',
              'font': 'font',
             'frame': 'sub_frame',
      'genericblock': 'unsupported',
       'generichide': 'generichide',
             'image': 'image',
       'inline-font': 'inline-font',
     'inline-script': 'inline-script',
             'media': 'media',
            'object': 'object',
 'object-subrequest': 'object',
             'other': 'other',
              'ping': 'other',
          'popunder': 'popunder',
             'popup': 'popup',
            'script': 'script',
        'stylesheet': 'stylesheet',
       'subdocument': 'sub_frame',
               'xhr': 'xmlhttprequest',
    'xmlhttprequest': 'xmlhttprequest',
            'webrtc': 'unsupported',
         'websocket': 'websocket'
};

/******************************************************************************/

FilterParser.prototype.reset = function() {
    this.action = BlockAction;
    this.anchor = 0;
    this.badFilter = false;
    this.dataType = undefined;
    this.dataStr = undefined;
    this.elemHiding = false;
    this.f = '';
    this.firstParty = false;
    this.thirdParty = false;
    this.party = AnyParty;
    this.fopts = '';
    this.hostnamePure = false;
    this.domainOpt = '';
    this.isRegex = false;
    this.raw = '';
    this.redirect = false;
    this.token = '*';
    this.tokenHash = this.noTokenHash;
    this.tokenBeg = 0;
    this.types = 0;
    this.important = 0;
    this.unsupported = false;
    return this;
};

/******************************************************************************/

FilterParser.prototype.bitFromType = function(type) {
    return 1 << ((typeNameToTypeValue[type] >>> 4) - 1);
};

/******************************************************************************/

// https://github.com/chrisaljoudi/uBlock/issues/589
// Be ready to handle multiple negated types

FilterParser.prototype.parseTypeOption = function(raw, not) {
    var typeBit = this.bitFromType(this.toNormalizedType[raw]);

    if ( !not ) {
        this.types |= typeBit;
        return;
    }

    // Non-discrete network types can't be negated.
    if ( (typeBit & this.allNetRequestTypeBits) === 0 ) {
        return;
    }

    // Negated type: set all valid network request type bits to 1
    if (
        (typeBit & this.allNetRequestTypeBits) !== 0 &&
        (this.types & this.allNetRequestTypeBits) === 0
    ) {
        this.types |= this.allNetRequestTypeBits;
    }
    this.types &= ~typeBit;
};

/******************************************************************************/

FilterParser.prototype.parsePartyOption = function(firstParty, not) {
    if ( firstParty ) {
        not = !not;
    }
    if ( not ) {
        this.firstParty = true;
        this.party = this.thirdParty ? AnyParty : FirstParty;
    } else {
        this.thirdParty = true;
        this.party = this.firstParty ? AnyParty : ThirdParty;
    }
};

/******************************************************************************/

FilterParser.prototype.parseDomainOption = function(s) {
    if ( this.reHasUnicode.test(s) ) {
        var hostnames = s.split('|'),
            i = hostnames.length;
        while ( i-- ) {
            if ( this.reHasUnicode.test(hostnames[i]) ) {
                hostnames[i] = punycode.toASCII(hostnames[i]);
            }
        }
        s = hostnames.join('|');
    }
    if ( this.reBadDomainOptChars.test(s) ) {
        return '';
    }
    return s;
};

/******************************************************************************/

FilterParser.prototype.parseOptions = function(s) {
    this.fopts = s;
    var opts = s.split(',');
    var opt, not;
    for ( var i = 0; i < opts.length; i++ ) {
        opt = opts[i];
        not = opt.startsWith('~');
        if ( not ) {
            opt = opt.slice(1);
        }
        if ( opt === 'third-party' || opt === '3p' ) {
            this.parsePartyOption(false, not);
            continue;
        }
        // https://issues.adblockplus.org/ticket/616
        // `generichide` concept already supported, just a matter of
        // adding support for the new keyword.
        if ( opt === 'elemhide' || opt === 'generichide' ) {
            if ( not === false ) {
                this.parseTypeOption('generichide', false);
                continue;
            }
            this.unsupported = true;
            break;
        }
        // Test before handling all other types.
        if ( opt.startsWith('redirect=') ) {
            if ( this.action === BlockAction ) {
                this.redirect = true;
                continue;
            }
            this.unsupported = true;
            break;
        }
        if ( this.toNormalizedType.hasOwnProperty(opt) ) {
            this.parseTypeOption(opt, not);
            continue;
        }
        // https://github.com/gorhill/uBlock/issues/2294
        // Detect and discard filter if domain option contains nonsensical
        // characters.
        if ( opt.startsWith('domain=') ) {
            this.domainOpt = this.parseDomainOption(opt.slice(7));
            if ( this.domainOpt === '' ) {
                this.unsupported = true;
                break;
            }
            continue;
        }
        if ( opt === 'important' ) {
            this.important = Important;
            continue;
        }
        if ( opt === 'first-party' || opt === '1p' ) {
            this.parsePartyOption(true, not);
            continue;
        }
        if ( opt.startsWith('csp=') ) {
            if ( opt.length > 4 && this.reBadCSP.test(opt) === false ) {
                this.parseTypeOption('data', not);
                this.dataType = 'csp';
                this.dataStr = opt.slice(4).trim();
            }
            continue;
        }
        if ( opt === 'csp' && this.action === AllowAction ) {
            this.parseTypeOption('data', not);
            this.dataType = 'csp';
            this.dataStr = '';
            continue;
        }
        // Used by Adguard, purpose is unclear -- just ignore for now.
        if ( opt === 'empty' ) {
            continue;
        }
        // https://github.com/uBlockOrigin/uAssets/issues/192
        if ( opt === 'badfilter' ) {
            this.badFilter = true;
            continue;
        }
        // Unrecognized filter option: ignore whole filter.
        this.unsupported = true;
        break;
    }
};

/******************************************************************************/

// https://github.com/gorhill/uBlock/issues/1943#issuecomment-243188946
//   Convert websocket-related filter where possible to a format which
//   can be handled using CSP injection.

FilterParser.prototype.translate = function() {
    var dataTypeBit = this.bitFromType('data');

    if ( this.cantWebsocket && this.reWebsocketAny.test(this.f) ) {
        this.f = '*';
        this.types = dataTypeBit;
        this.dataType = 'csp';
        this.dataStr = "connect-src https: http:";
        // https://bugs.chromium.org/p/chromium/issues/detail?id=669086
        // TODO: remove when most users are beyond Chromium v56
        if (
            vAPI.webextFlavor.soup.has('chromium') &&
            vAPI.webextFlavor.major < 57
        ) {
            this.dataStr += '; frame-src *';
        }
        return;
    }

    // Broad |data:-based filters.
    if ( this.f === 'data:' ) {
        switch ( this.types ) {
        case 0:
            this.f = '*';
            this.types = dataTypeBit;
            this.dataType = 'csp';
            this.dataStr = "default-src 'self' * blob: 'unsafe-inline' 'unsafe-eval'";
            break;
        case this.bitFromType('script'):
            this.f = '*';
            this.types = dataTypeBit;
            this.dataType = 'csp';
            this.dataStr = "script-src 'self' * blob: 'unsafe-inline' 'unsafe-eval'";
            break;
        case this.bitFromType('sub_frame'):
            this.f = '*';
            this.types = dataTypeBit;
            this.dataType = 'csp';
            this.dataStr = "frame-src 'self' * blob:";
            break;
        case this.bitFromType('script') | this.bitFromType('sub_frame'):
            this.f = '*';
            this.types = dataTypeBit;
            this.dataType = 'csp';
            this.dataStr = "frame-src 'self' * blob:; script-src 'self' * blob: 'unsafe-inline' 'unsafe-eval';";
            break;
        default:
            break;
        }
    }

    // Broad |blob:-based filters.
    if ( this.f === 'blob:' ) {
        switch ( this.types ) {
        case 0:
            this.f = '*';
            this.types = dataTypeBit;
            this.dataType = 'csp';
            this.dataStr = "default-src 'self' * data: 'unsafe-inline' 'unsafe-eval'";
            break;
        case this.bitFromType('script'):
            this.f = '*';
            this.types = dataTypeBit;
            this.dataType = 'csp';
            this.dataStr = "script-src 'self' * data: 'unsafe-inline' 'unsafe-eval'";
            break;
        case this.bitFromType('sub_frame'):
            this.f = '*';
            this.types = dataTypeBit;
            this.dataType = 'csp';
            this.dataStr = "frame-src 'self' * data:";
            break;
        case this.bitFromType('script') | this.bitFromType('sub_frame'):
            this.f = '*';
            this.types = dataTypeBit;
            this.dataType = 'csp';
            this.dataStr = "frame-src 'self' * data:; script-src 'self' * data: 'unsafe-inline' 'unsafe-eval';";
            break;
        default:
            break;
        }
    }
};

/*******************************************************************************

    anchor: bit vector
        0000 (0x0): no anchoring
        0001 (0x1): anchored to the end of the URL.
        0010 (0x2): anchored to the start of the URL.
        0011 (0x3): anchored to the start and end of the URL.
        0100 (0x4): anchored to the hostname of the URL.
        0101 (0x5): anchored to the hostname and end of the URL.

**/

FilterParser.prototype.parse = function(raw) {
    // important!
    this.reset();

    var s = this.raw = raw;

    // plain hostname? (from HOSTS file)
    if ( this.reHostnameRule1.test(s) ) {
        this.f = s;
        this.hostnamePure = true;
        this.anchor |= 0b100;
        return this;
    }

    // element hiding filter?
    var pos = s.indexOf('#');
    if ( pos !== -1 ) {
        var c = s.charAt(pos + 1);
        if ( c === '#' || c === '@' ) {
            console.error('static-net-filtering.js > unexpected cosmetic filters');
            this.elemHiding = true;
            return this;
        }
    }

    // block or allow filter?
    // Important: this must be executed before parsing options
    if ( s.startsWith('@@') ) {
        this.action = AllowAction;
        s = s.slice(2);
    }

    // options
    // https://github.com/gorhill/uBlock/issues/842
    // - ensure sure we are not dealing with a regex-based filter.
    // - lookup the last occurrence of `$`.
    if ( s.startsWith('/') === false || s.endsWith('/') === false ) {
        pos = s.lastIndexOf('$');
        if ( pos !== -1 ) {
            // https://github.com/gorhill/uBlock/issues/952
            //   Discard Adguard-specific `$$` filters.
            if ( s.indexOf('$$') !== -1 ) {
                this.unsupported = true;
                return this;
            }
            this.parseOptions(s.slice(pos + 1));
            // https://github.com/gorhill/uBlock/issues/2283
            //   Abort if type is only for unsupported types, otherwise
            //   toggle off `unsupported` bit.
            if ( this.types & this.unsupportedTypeBit ) {
                this.types &= ~this.unsupportedTypeBit;
                if ( this.types === 0 ) {
                    this.unsupported = true;
                    return this;
                }
            }
            s = s.slice(0, pos);
        }
    }

    // regex?
    if ( s.startsWith('/') && s.endsWith('/') && s.length > 2 ) {
        this.isRegex = true;
        this.f = s.slice(1, -1);
        // https://github.com/gorhill/uBlock/issues/1246
        // If the filter is valid, use the corrected version of the source
        // string -- this ensure reverse-lookup will work fine.
        this.f = normalizeRegexSource(this.f);
        if ( this.f === '' ) {
            console.error(
                "uBlock Origin> discarding bad regular expression-based network filter '%s': '%s'",
                raw,
                normalizeRegexSource.message
            );
            this.unsupported = true;
        }
        return this;
    }

    // hostname-anchored
    if ( s.startsWith('||') ) {
        this.anchor |= 0x4;
        s = s.slice(2);

        // convert hostname to punycode if needed
        // https://github.com/gorhill/uBlock/issues/2599
        if ( this.reHasUnicode.test(s) ) {
            var matches = this.reIsolateHostname.exec(s);
            if ( matches ) {
                s = (matches[1] !== undefined ? matches[1] : '') +
                    punycode.toASCII(matches[2]) +
                    matches[3];
                //console.debug('µBlock.staticNetFilteringEngine/FilterParser.parse():', raw, '=', s);
            }
        }

        // https://github.com/chrisaljoudi/uBlock/issues/1096
        if ( s.startsWith('^') ) {
            this.unsupported = true;
            return this;
        }

        // plain hostname? (from ABP filter list)
        // https://github.com/gorhill/uBlock/issues/1757
        // A filter can't be a pure-hostname one if there is a domain or csp
        // option present.
        if ( this.reHostnameRule2.test(s) ) {
            this.f = s.replace(this.reCleanupHostnameRule2, '');
            this.hostnamePure = true;
            return this;
        }
    }
    // left-anchored
    else if ( s.startsWith('|') ) {
        this.anchor |= 0x2;
        s = s.slice(1);
    }

    // right-anchored
    if ( s.endsWith('|') ) {
        this.anchor |= 0x1;
        s = s.slice(0, -1);
    }

    // https://github.com/gorhill/uBlock/issues/1669#issuecomment-224822448
    // remove pointless leading *.
    // https://github.com/gorhill/uBlock/issues/3034
    // - We can remove anchoring if we need to match all at the start.
    if ( s.startsWith('*') ) {
        s = s.replace(/^\*+([^%0-9a-z])/i, '$1');
        this.anchor &= ~0x6;
    }
    // remove pointless trailing *
    // https://github.com/gorhill/uBlock/issues/3034
    // - We can remove anchoring if we need to match all at the end.
    if ( s.endsWith('*') ) {
        s = s.replace(/([^%0-9a-z])\*+$/i, '$1');
        this.anchor &= ~0x1;
    }

    // nothing left?
    if ( s === '' ) {
        s = '*';
    }

    // https://github.com/gorhill/uBlock/issues/1047
    // Hostname-anchored makes no sense if matching all requests.
    if ( s === '*' ) {
        this.anchor = 0;
    }

    // This might look weird but we gain memory footprint by not going through
    // toLowerCase(), at least on Chromium. Because copy-on-write?

    this.f = this.reHasUppercase.test(s) ? s.toLowerCase() : s;

    // Convenience:
    //   Convert special broad filters for non-webRequest aware types into
    //   `csp` filters wherever possible.
    if ( this.anchor & 0x2 && this.party === 0 ) {
        this.translate();
    }

    return this;
};

FilterParser.prototype.parse("-ad-ero-");


/******************************************************************************/

// Given a string, find a good token. Tokens which are too generic, i.e. very
// common with a high probability of ending up as a miss, are not
// good. Avoid if possible. This has a *significant* positive impact on
// performance.
// These "bad tokens" are collated manually.

// Hostname-anchored with no wildcard always have a token index of 0.
var reHostnameToken = /^[0-9a-z]+/;
var reGoodToken = /[%0-9a-z]{2,}/g;
var reRegexToken = /[%0-9A-Za-z]{2,}/g;
var reRegexTokenAbort = /[([]/;
var reRegexBadPrefix = /(^|[^\\]\.|[*?{}\\])$/;
var reRegexBadSuffix = /^([^\\]\.|\\[dw]|[([{}?*]|$)/;

var badTokens = new Set([
    'com',
    'http',
    'https',
    'icon',
    'images',
    'img',
    'js',
    'net',
    'news',
    'www'
]);

FilterParser.prototype.findFirstGoodToken = function() {
    reGoodToken.lastIndex = 0;
    var s = this.f,
        matches, lpos,
        badTokenMatch = null;
    while ( (matches = reGoodToken.exec(s)) !== null ) {
        // https://github.com/gorhill/uBlock/issues/997
        // Ignore token if preceded by wildcard.
        lpos = matches.index;
        if ( lpos !== 0 && s.charCodeAt(lpos - 1) === 0x2A /* '*' */ ) {
            continue;
        }
        if ( s.charCodeAt(reGoodToken.lastIndex) === 0x2A /* '*' */ ) {
            continue;
        }
        if ( badTokens.has(matches[0]) ) {
            if ( badTokenMatch === null ) {
                badTokenMatch = matches;
            }
            continue;
        }
        return matches;
    }
    return badTokenMatch;
};

FilterParser.prototype.extractTokenFromRegex = function() {
    reRegexToken.lastIndex = 0;
    var s = this.f,
        matches, prefix;
    while ( (matches = reRegexToken.exec(s)) !== null ) {
        prefix = s.slice(0, matches.index);
        if ( reRegexTokenAbort.test(prefix) ) { return; }
        if (
            reRegexBadPrefix.test(prefix) ||
            reRegexBadSuffix.test(s.slice(reRegexToken.lastIndex))
        ) {
            continue;
        }
        this.token = matches[0].toLowerCase();
        this.tokenHash = µb.urlTokenizer.tokenHashFromString(this.token);
        this.tokenBeg = matches.index;
        if ( badTokens.has(this.token) === false ) { break; }
    }
};

/******************************************************************************/

// https://github.com/chrisaljoudi/uBlock/issues/1038
// Single asterisk will match any URL.

// https://github.com/gorhill/uBlock/issues/2781
//   For efficiency purpose, try to extract a token from a regex-based filter.

FilterParser.prototype.makeToken = function() {
    if ( this.isRegex ) {
        this.extractTokenFromRegex();
        return;
    }

    if ( this.f === '*' ) { return; }

    var matches = null;
    if ( (this.anchor & 0x4) !== 0 && this.f.indexOf('*') === -1 ) {
        matches = reHostnameToken.exec(this.f);
    }
    if ( matches === null ) {
        matches = this.findFirstGoodToken();
    }
    if ( matches !== null ) {
        this.token = matches[0];
        this.tokenHash = µb.urlTokenizer.tokenHashFromString(this.token);
        this.tokenBeg = matches.index;
    }
};

