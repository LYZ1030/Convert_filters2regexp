class convertFilter2RegExp {
    constructor(){
        this.reHostnameRule1 = /^[0-9a-z][0-9a-z.-]*[0-9a-z]$/i; 
        this.reHostnameRule2 = /^[0-9a-z][0-9a-z.-]*[0-9a-z]\^?$/i;
        this.reCleanupHostnameRule2 = /\^$/g;
        this.reIsolateHostname = /^(\*?\.)?([^\x00-\x24\x26-\x2C\x2F\x3A-\x5E\x60\x7B-\x7F]+)(.*)/;
        this.reCleanupHostnameRule2 = /\^$/g;
        this.reHasUnicode = /[^\x00-\x7F]/;
    }

    parse(filter){
        var s = this.raw = filter;
        this.anchor = 0;

        // plain hostname? (from HOSTS file)
        if ( this.reHostnameRule1.test(s) ) {
            this.f = s;
            this.hostnamePure = true;
            this.anchor |= 0b100;
            //console.log("1");
            //return this;
        }

        // element hiding filter?
        var pos = s.indexOf('#');
        if ( pos !== -1 ) {
            /*
            var c = s.charAt(pos + 1);
            if ( c === '#' || c === '@' ) {
                console.error('static-net-filtering.js > unexpected cosmetic filters');
                this.elemHiding = true;
                //console.log("2");
                return this;
            }*/
            return "";
        }

        // block or allow filter?
        // Important: this must be executed before parsing options
        if ( s.startsWith('@@') ) {
            s = s.slice(2);
            //console.log("3");
            return "";
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
                    console.log("4");
                    return "";
                }
                s = s.slice(0, pos);
            }
        }

        // regex?
        if ( s.startsWith('/') && s.endsWith('/') && s.length > 2 ) {
            this.isRegex = true;
            return s.slice(1, -1);
        }

        if (s.startsWith('||')){
            s = s.slice(2);
            this.anchor |= 0b100;

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
                console.log("6");
                return "";
            }

            // plain hostname? (from ABP filter list)
            // https://github.com/gorhill/uBlock/issues/1757
            // A filter can't be a pure-hostname one if there is a domain or csp
            // option present.
            /*
            if ( this.reHostnameRule2.test(s) ) {
                this.f = s.replace(this.reCleanupHostnameRule2, '');
                this.hostnamePure = true;
                //console.log("7");
                //return this;
            }*/
        } 
        
        else if (s[0] === '|' && s.substr(-1) === '|'){
            s = s.slice(1, -1);
            this.anchor |= 0b011;
        }
        
        else if (s[0] === '|'){
            s = s.substring(1);
            this.anchor |= 0b010;
        }
        
        else if (s.substr(-1) === '|'){
            s = s.slice(0, -1);
            this.anchor = 0b001;
        }
        
        var source = s
        .replace(/[.+$?{}()|[\]\\]/g, '\\$&') //escape special charactor
        .replace(/\^/g, '(?:[^%.0-9a-z_-]|$)') // replace seprator
        .replace(/^\*+|\*+$/g, "") // remove wildcards at the begining and end
        .replace(/\*/g, '[^ ]*?') // replace * in the middle
        
        if ( this.anchor & 0b010 ) {
            source = '^' + source;
        }
        if ( this.anchor & 0b001 ) {
            source += '$';
        }
        
        return source;
    }
}

const normalizeRegexSource = function(s) {
    try {
        const re = new RegExp(s);
        return re.source;
    } catch (ex) {
        normalizeRegexSource.message = ex.toString();
    }
    return '';
};


const fs = require('fs');
const punycode = require('punycode');
/*
var str = fs.readFileSync('easylist.txt','utf8');
console.log(str);
*/
var Obj = new convertFilter2RegExp();
var lineReader = require('readline').createInterface({
    input: require('fs').createReadStream('easylist.txt')
});
  
lineReader.on('line', function (line) {
    line = Obj.parse(line);
    if(line !== ""){
        line = new RegExp(line, 'i')
        fs.appendFile('RegExps', line + '\n', function (err) {
            if (err) throw err;
            console.log('Saved!');
        });
    }
});





