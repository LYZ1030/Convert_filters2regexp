
var regExprs = [];

function readRegexprs(callback){
    var lineReader = require('readline').createInterface({
        input: require('fs').createReadStream('RegExps')
    });
    lineReader.on('line', function (line) {
        regExprs.push(line);
    });
    callback();
}

readRegexprs(function(){
    console.log(regExprs.length)
})
//console.log(regExprs.length);
