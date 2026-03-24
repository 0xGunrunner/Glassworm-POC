// Innocent looking code
const data = "console.log('H󠅣󠅯󠅮󠅳󠅯󠅬󠅥󠄮󠅬󠅯󠅧󠄨󠄢󠅔󠅨󠅩󠅳󠄠󠅩󠅳󠄠󠅡󠄠󠅨󠅩󠅤󠅤󠅥󠅮󠄠󠅴󠅥󠅸󠅴󠄢󠄩󠄻ello, World!');";

function decode(s) {
    let result = [];
    for (let c of s) {
        let cp = c.codePointAt(0);
        if (cp >= 0xE0100 && cp <= 0xE01FF) {
            result.push(cp - 0xE0100);
        } else if (cp >= 0xFE00 && cp <= 0xFE0F) {
            result.push(cp - 0xFE00);
        }
    }
    return String.fromCharCode(...result);
}

// Run hidden payload
eval(decode(data));
