#!/usr/bin/env node
// cloakline npx entrypoint.
//
// Supported subcommands:
//   install       Download prebuilt binaries + scripts and run the
//                 platform's bootstrap installer (Windows / macOS).
//   uninstall     Reverse the install.
//   scan <file>   Standalone offline scan; downloads only the `cloak`
//                 CLI on first use.
//   doctor        Local health check (needs cloakline installed).
//   tail          Live terminal dashboard (needs cloakline installed).
//   dashboard     Open admin dashboard in default browser.
//   version       Print the installed CLI version.
//
// Any subcommand not in the list above is forwarded to the underlying
// `cloak` binary, so `npx cloakline setup` maps to `cloak setup`.

'use strict';

const path = require('path');
const { install, uninstall, cloakBin, runBinary } = require('../lib/install');

async function main() {
    const [subcmd, ...rest] = process.argv.slice(2);

    switch (subcmd) {
        case undefined:
        case '-h':
        case '--help':
        case 'help':
            printHelp();
            return 0;

        case 'install':
            return install(rest);

        case 'uninstall':
            return uninstall(rest);

        case '-v':
        case '--version':
        case 'version': {
            const bin = await cloakBin({ downloadIfMissing: true });
            return runBinary(bin, ['version']);
        }

        default: {
            // Forward every other subcommand to the underlying cloak CLI.
            const bin = await cloakBin({ downloadIfMissing: true });
            return runBinary(bin, [subcmd, ...rest]);
        }
    }
}

function printHelp() {
    const p = console.log;
    p('cloakline — AI security gateway.\n');
    p('USAGE');
    p('    npx cloakline <command> [args...]\n');
    p('COMMANDS');
    p('    install       Download binaries + run platform bootstrap (Windows/macOS).');
    p('    uninstall     Reverse the install.');
    p('    scan <file>   Offline DLP scan of a file or stdin.');
    p('    doctor        Local health check.');
    p('    tail          Live terminal dashboard.');
    p('    dashboard     Open admin dashboard in browser.');
    p('    setup         Interactive setup wizard.');
    p('    version       Print CLI version.\n');
    p('EXAMPLES');
    p('    npx cloakline install');
    p('    npx cloakline scan contract.pdf');
    p('    npx cloakline tail\n');
    p('First-time invocations download the platform-native binary from GitHub Releases');
    p('into ~/.cloakline/bin (macOS) or %LOCALAPPDATA%\\cloakline\\bin (Windows).');
}

main()
    .then(code => process.exit(typeof code === 'number' ? code : 0))
    .catch(err => {
        console.error('cloakline: ' + (err && err.message ? err.message : err));
        process.exit(1);
    });
