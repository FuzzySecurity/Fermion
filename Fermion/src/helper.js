const EXTRA_ARG_PREFIX="FERMION_ARG="
function getExtraArgs() {
    var args = []
    for (let i = window.process.argv.length - 1; i >= 0; i--) {
        arg = window.process.argv[i];
        if (arg.startsWith(EXTRA_ARG_PREFIX)) {
            args.push(atob(arg.substr(EXTRA_ARG_PREFIX.length)))
        }
    }
    return args;
}

function wrapExtraArgs(args) {
    return args.map((x) => EXTRA_ARG_PREFIX + btoa(x))
}

module.exports = {
    getExtraArgs: getExtraArgs,
    wrapExtraArgs: wrapExtraArgs,
}
