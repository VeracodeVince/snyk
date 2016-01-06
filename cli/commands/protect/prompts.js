module.exports = {
  getUpdatePrompts: getUpdatePrompts,
  getPatchPrompts: getPatchPrompts,
  getIgnorePrompts: getIgnorePrompts,
  getPrompts: getPrompts,
  nextSteps: nextSteps,
  startOver: startOver,
};

var _ = require('lodash');
var semver = require('semver');
var debug = require('debug')('snyk');
var protect = require('../../../lib/protect');
var moduleToObject = require('snyk-module');
var undefsafe = require('undefsafe');
var config = require('../../../lib/config');
var snyk = require('../../../lib/');

// via http://stackoverflow.com/a/4760279/22617
function sort(prop) {
  var sortOrder = 1;
  if (prop[0] === '-') {
    sortOrder = -1;
    prop = prop.substr(1);
  }

  return function (a, b) {
    var result = (a[prop] < b[prop]) ? -1 : (a[prop] > b[prop]) ? 1 : 0;
    return result * sortOrder;
  };
}

function sortUpgradePrompts(a, b) {
  var res = 0;

  // first sort by module affected
  if (!a.from[1]) {
    return -1;
  }

  if (!b.from[1]) {
    return 1;
  }

  var pa = moduleToObject(a.from[1]);
  var pb = moduleToObject(b.from[1]);
  res = sort('name')(pa, pb);
  if (res !== 0) {
    return res;
  }

  // we should have the same module, so the depth should be the same
  if (a.upgradePath[1] && b.upgradePath[1]) {
    // put upgrades ahead of patches
    if (b.upgradePath[1] === false) {
      return 1;
    }
    var pua = moduleToObject(a.upgradePath[1]);
    var pub = moduleToObject(b.upgradePath[1]);

    res = semver.compare(pua.version, pub.version) * -1;

    if (res !== 0) {
      return res;
    }
  } else {
    if (a.upgradePath[1]) {
      return -1;
    }

    if (b.upgradePath[1]) {
      return 1;
    }

    // if no upgrade, then hopefully a patch
    res = sort('publicationTime')(b, a);
  }

  return res;
}

function sortPatchPrompts(a, b) {
  var res = 0;

  // first sort by module affected
  var afrom = a.from.slice(1).pop();
  var bfrom = b.from.slice(1).pop();

  if (!afrom) {
    return -1;
  }

  if (!bfrom[1]) {
    return 1;
  }

  var pa = moduleToObject(afrom);
  var pb = moduleToObject(bfrom);
  res = sort('name')(pa, pb);
  if (res !== 0) {
    return res;
  }

  // if no upgrade, then hopefully a patch
  res = sort('publicationTime')(b, a);

  return res;
}

function stripInvalidPatches(vulns) {
  // strip the irrelevant patches from the vulns at the same time, collect
  // the unique package vulns
  return vulns.map(function (vuln) {
    // strip verbose meta
    delete vuln.description;
    delete vuln.credit;

    if (vuln.patches) {
      vuln.patches = vuln.patches.filter(function (patch) {
        return semver.satisfies(vuln.version, patch.version);
      });

      // sort by patchModification, then pick the latest one
      vuln.patches = vuln.patches.sort(function (a, b) {
        return b.modificationTime < a.modificationTime ? -1 : 1;
      }).slice(0, 1);

      // FIXME hack to give all the patches IDs if they don't already
      if (vuln.patches[0] && !vuln.patches[0].id) {
        vuln.patches[0].id = vuln.patches[0].urls[0].split('/').slice(-1).pop();
      }
    }

    return vuln;
  });

}

function getPrompts(vulns, policy) {
  return getUpdatePrompts(vulns, policy)
                  .concat(getPatchPrompts(vulns, policy))
                  .concat(getIgnorePrompts(vulns, policy));
}

function getPatchPrompts(vulns, policy) {
  debug('getPatchPrompts');
  if (!vulns || vulns.length === 0) {
    return [];
  }

  var res = stripInvalidPatches(_.cloneDeep(vulns));

  // sort by vulnerable package and the largest version
  res.sort(sortPatchPrompts);

  // console.log(res.map(_ => `${_.name}@${_.version}`));

  var copy = {};
  var offset = 0;
  // mutate our objects so we can try to group them
  // note that I use slice first becuase the `res` array will change length
  // and `reduce` _really_ doesn't like when you change the array under
  // it's feet
  res.slice(0).reduce(function (acc, curr, i, all) {
    var upgrades = curr.upgradePath[1];
    // otherwise it's a patch and that's hidden for now
    if (!upgrades && curr.patches && curr.patches.length) {
      // TODO allow for cross over patches on modules (i.e. patch can work
      // on A-1 and A-2)
      var last = curr.id; //curr.from.slice(-1).pop();

      if (acc[curr.id]) {
        last = curr.id;
      } else {
        // try to find the right vuln id based on the
        last = (all.filter(function (vuln) {
          var patch = vuln.patches[0];

          // don't select the one we're looking at

          if (curr.id === vuln.id) {
            return false;
          }

          // only look at packages with the same name
          if (curr.name !== vuln.name || !patch) {
            return false;
          }

          // and ensure the patch can be applied to *our* module version
          if (semver.satisfies(curr.version, patch.version)) {

            // finally make sure the publicationTime is newer than the curr
            // vulnerability
            if (curr.publicationTime < vuln.publicationTime) {
              debug('found alternative location for %s@%s (%s by %s) in vuln %s',
                curr.name, curr.version, patch.version, curr.id, vuln.id);
              return true;
            }
          }
        }).shift() || curr).id;

      }

      if (!acc[last]) {
        // only copy the biggest change
        copy[last] = _.cloneDeep(curr);
        acc[last] = curr;
        return acc;
      }

      // only happens on the 2nd time around
      if (!acc[last].grouped) {
        acc[last].grouped = {
          affected: moduleToObject(acc[last].name + '@' + acc[last].version),
          main: true,
          id: acc[last].id + '-' + i,
          count: 1,
          upgrades: [acc[last].from],
          patch: true,
        };

        acc[last].grouped.affected.full = acc[last].name;

        // splice this vuln into the list again so if the user choses to review
        // they'll get this individual vuln and remediation
        copy[last].grouped = {
          main: false,
          requires: acc[last].grouped.id,
        };

        res.splice(i + offset, 0, copy[last]);
        offset++;
      }

      // if (acc[last].grouped.affected.full.indexOf(curr.version) === -1) {
      //   acc[last].grouped.affected.full += ' / ' + curr.version;
      // }

      acc[last].grouped.count++;

      curr.grouped = {
        main: false,
        requires: acc[last].grouped.id,
      };

      // add the from path to our group upgrades if we don't have it already
      var have = !!acc[last].grouped.upgrades.filter(function (from) {
        return from.join(' ') === curr.from.join(' ');
      }).length;

      if (!have) {
        acc[last].grouped.upgrades.push(curr.from);
      }
    }

    return acc;
  }, {});

  // FIXME this should not just strip those that have an upgrade path, but
  // take into account the previous answers, and if the package has been
  // upgraded, it should be left *out* of our list.
  res = res.filter(function (curr) {
    if (curr.upgradePath[1]) {
      return false;
    }

    if (!curr.patches || curr.patches.length === 0) {
      return false;
    }

    return true;
  });

  // console.log(res.map(_ => _.grouped));
  var prompts = generatePrompt(res, policy);


  return prompts;

}

function getIgnorePrompts(vulns, policy) {
  debug('getIgnorePrompts');
  if (!vulns || vulns.length === 0) {
    return [];
  }

  var res = stripInvalidPatches(_.cloneDeep(vulns)).filter(function (vuln) {
    // remove all patches and updates

    // if there's any upgrade available
    if (vuln.upgradePath && vuln.upgradePath[1]) {
      return false;
    }

    if (vuln.patches && vuln.patches.length) {
      return false;
    }

    return true;
  });

  var prompts = generatePrompt(res, policy);

  return prompts;

}

function getUpdatePrompts(vulns, policy) {
  debug('getUpdatePrompts');
  if (!vulns || vulns.length === 0) {
    return [];
  }

  var res = stripInvalidPatches(_.cloneDeep(vulns));

  // sort by vulnerable package and the largest version
  res.sort(sortUpgradePrompts);

  var copy = null;
  var offset = 0;
  // mutate our objects so we can try to group them
  // note that I use slice first becuase the `res` array will change length
  // and `reduce` _really_ doesn't like when you change the array under
  // it's feet
  res.slice(0).reduce(function (acc, curr, i) {
    var from = curr.from[1];

    if (!acc[from]) {
      // only copy the biggest change
      copy = _.cloneDeep(curr);
      acc[from] = curr;
      return acc;
    }

    var upgrades = curr.upgradePath.slice(-1).shift();
    // otherwise it's a patch and that's hidden for now
    if (upgrades && curr.upgradePath[1]) {
      if (!acc[from].grouped) {
        acc[from].grouped = {
          affected: moduleToObject(from),
          main: true,
          id: acc[from].id + '-' + i,
          count: 1,
          upgrades: [],
        };
        acc[from].grouped.affected.full = from;

        // splice this vuln into the list again so if the user choses to review
        // they'll get this individual vuln and remediation
        copy.grouped = {
          main: false,
          requires: acc[from].grouped.id,
        };

        res.splice(i + offset, 0, copy);
        offset++;
      }

      acc[from].grouped.count++;

      curr.grouped = {
        main: false,
        requires: acc[from].grouped.id,
      };

      var p = moduleToObject(upgrades);
      if (p.name !== acc[from].grouped.affected.name &&
        (' ' + acc[from].grouped.upgrades.join(' ') + ' ')
          .indexOf(p.name + '@') === -1) {
        debug('+ adding %s to upgrades', upgrades);
        acc[from].grouped.upgrades.push(upgrades);
      }
    }

    return acc;
  }, {});

  // now strip anything that doesn't have an upgrade path
  res = res.filter(function (curr) {
    return !!curr.upgradePath[1];
  });

  var prompts = generatePrompt(res, policy);

  return prompts;
}

function generatePrompt(vulns, policy) {
  if (!vulns) {
    vulns = []; // being defensive, but maybe we should throw an error?
  }

  var skipAction = {
    value: 'skip', // the value that we get in our callback
    key: 's',
    name: 'Skip', // the text the user sees
  };

  var ignoreAction = {
    value: 'ignore',
    key: 'i',
    meta: { // arbitrary data that we'll merged into the `value` later on
      days: 30,
    },
    short: 'Ignore',
    name: 'Set to ignore for 30 days (updates policy)',
  };

  var patchAction = {
    value: 'patch',
    key: 'p',
    short: 'Patch',
    name: 'Patch (modifies files locally, updates policy for `snyk protect` ' +
      'runs)',
  };

  var updateAction = {
    value: 'update',
    key: 'u',
    short: 'Upgrade',
    name: null, // updated below to the name of the package to update
  };

  var prompts = vulns.map(function (vuln, i) {
    var id = vuln.id || ('node-' + vuln.name + '@' + vuln.below);

    id += '-' + i;

    // make complete copies of the actions, otherwise we'll mutate the object
    var ignore = _.cloneDeep(ignoreAction);
    var skip = _.cloneDeep(skipAction);
    var patch = _.cloneDeep(patchAction);
    var update = _.cloneDeep(updateAction);
    var review = {
      value: 'review',
      short: 'Review',
      name: 'Review vulnerabilities separately',
    };

    var choices = [];

    var from = vuln.from.slice(1).filter(Boolean).shift();

    // FIXME this should be handled a litle more gracefully
    if (vuln.from.length === 1) {
      console.log('');
      var error = new Error(vuln.upgradePath[0]);
      error.code = 'updatepackage';
      throw error;
    }
    var vulnIn = vuln.from.slice(-1).pop();
    var severity = vuln.severity[0].toUpperCase() + vuln.severity.slice(1);

    var infoLink = '- info: ' + config.ROOT;
    var messageIntro;
    var fromText = false;
    var group = vuln.grouped && vuln.grouped.main ? vuln.grouped : false;

    if (group) {
      infoLink += '/package/npm/' + group.affected.name + '/' +
        group.affected.version;
      var joiningText = group.patch ? ' in ' : ' via ';
      messageIntro = group.count + ' vulnerabilities introduced' + joiningText +
        group.affected.full;
    } else {
      infoLink += '/vuln/' + vuln.id;
      messageIntro = severity + ' severity vulnerability found in ' + vulnIn +
        ', introduced via ' + from;
      fromText = (from !== vuln.from.slice(1).join(' > ') ?
          '- from: ' + vuln.from.slice(1).join(' > ') : '');
    }

    var note = false;
    if (vuln.note) {
      if (group && group.patch) {

      } else {
        note = '- note: ' + vuln.note;
      }
    }

    var res = {
      when: function (answers) {
        var res = true;
        // only show this question if the user chose to review the details
        // of the vuln
        if (vuln.grouped && !vuln.grouped.main) {
          // find how they answered on the top level question
          var groupAnswer = Object.keys(answers).map(function (key) {
            if (answers[key].meta) {
              if (answers[key].meta.groupId === vuln.grouped.requires) {
                return answers[key];
              }
            }
            return false;
          }).filter(Boolean);

          if (!groupAnswer.length) {
            debug('no group answer: show %s when %s', vuln.id, false);
            return false;
          }

          // if we've upgraded, then stop asking
          var updatedTo = null;
          res = groupAnswer.filter(function (answer) {
            if (answer.choice === 'update') {
              updatedTo = answer;
              return true;
            }
          }).length === 0;

          if (!res) {
            // echo out what would be upgraded
            var via = 'Fixed through previous upgrade instruction to ' + updatedTo.vuln.upgradePath[1];
            console.log(['', messageIntro, infoLink, via].join('\n'));
          }
        }

        if (res) {
          console.log(''); // blank line between prompts...kinda lame, sorry
        }

        debug('final show %s when %s', vuln.id, res);

        return res; // true = show next
      },
      name: id,
      type: 'list',
      message: [messageIntro, fromText, infoLink, note, '  Remediation options']
        .filter(Boolean).join('\n')
    };

    var upgradeAvailable = vuln.upgradePath.some(function (pkg, i) {
      // if the upgade path is to upgrade the module to the same range the
      // user already asked for, then it means we need to just blow that
      // module away and re-install
      if (pkg && vuln.from.length > i && pkg === vuln.from[i]) {
        return true;
      }

      // if the upgradePath contains the first two elements, that is
      // the project itself (i.e. jsbin) then the direct dependency can be
      // upgraded. Note that if the first two elements
      if (vuln.upgradePath.slice(0, 2).filter(Boolean).length) {
        return true;
      }
    });

    // note: the language presented the user is "upgrade" rather than "update"
    // this change came long after all this code was written. I've decided
    // *not* to update all the variables referring to `update`, but just
    // to warn my dear code-reader that this is intentional.
    if (upgradeAvailable) {
      choices.push(update);
      var toPackage = vuln.upgradePath.filter(Boolean).shift();
      update.short = 'Upgrade to ' + toPackage;
      var out = 'Upgrade to ' + toPackage;
      var toPackageVersion = moduleToObject(toPackage).version;
      var diff = semver.diff(moduleToObject(from).version, toPackageVersion);
      var lead = '';
      var breaking = 'potentially breaking change';
      if (diff === 'major') {
        lead = ' (' + breaking + ', ';
      } else {
        lead = ' (';
      }

      lead += 'triggers upgrade to ';
      if (group && group.upgrades.length) {
        out += lead + group.upgrades.join(', ') + ')';
      } else {
        var last = vuln.upgradePath.slice(-1).shift();
        if (toPackage !== last) {
          out += lead + last + ')';
        } else if (diff === 'major') {
          out += ' (' + breaking + ')';
        }
      }
      update.name = out;
    } else {
      // No upgrade available (as per no patch)
      choices.push({
        value: 'skip',
        key: 'u',
        short: 'Upgrade (none available)',
        name: 'Upgrade (no sufficient upgrade available' +
          ', we\'ll notify you when there is one)',
      });
    }

    var patches = null;

    if (upgradeAvailable && group) {

    } else {
      if (vuln.patches && vuln.patches.length) {
        // check that the version we have has a patch available
        patches = protect.patchesForPackage({
          name: vuln.name,
          version: vuln.version,
        }, vuln);

        if (patches !== null) {
          if (!upgradeAvailable) {
            patch.default = true;
          }
          res.patches = patches;

          if (group) {
            patch.name = 'Patch the ' + group.count + ' vulnerabilities';
          }

          choices.push(patch);
        }
      }
    }

    // only show patch option if this is NOT a grouped upgrade
    if (upgradeAvailable === false || !group) {
      if (patches === null) {
        // add a disabled option saying that patch isn't available
        // note that adding `disabled: true` does nothing, so the user can
        // actually select this option. I'm not 100% it's the right thing,
        // but we'll keep a keen eye on user feedback.
        choices.push({
          value: 'skip',
          key: 'p',
          short: 'Patch (none available)',
          name: 'Patch (no patch available, we\'ll notify you when there is one)',
        });
      }
    }

    if (group) {
      review.meta = {
        groupId: group.id,
      };
      choices.push(review);
    }

    if (patches === null && !upgradeAvailable) {
      ignore.default = true;
    }

    choices.push(ignore);
    choices.push(skip);

    // look for a default - the `res.default` needs to be the index
    // of the choice, so we remap the choices to include the index, value of
    // choice and whether it was supposed to be a default. If the user is
    // updating their policy options, then we select the choice they had
    // before, otherwise we select the default
    res.default = (choices.map(function (choice, i) {
      return { i: i, default: choice.default };
    }).filter(function (choice) {
      return choice.default;
    }).shift() || { i: 0 }).i;

    // kludge to make sure that we get the vuln in the user selection
    res.choices = choices.map(function (choice) {
      var value = choice.value;
      // this allows us to pass more data into the inquirer results
      if (vuln.grouped && !vuln.grouped.main) {
        if (!choice.meta) {
          choice.meta = {};
        }
        choice.meta.groupId = vuln.grouped.requires;
      }
      choice.value = {
        meta: choice.meta,
        vuln: vuln,
        choice: value, // this is the string "update", "ignore", etc
      };
      return choice;
    });

    res.vuln = vuln;

    return res;
  });

  // zip together every prompt and a prompt asking "why", note that the `when`
  // callback controls whether not to prompt the user with this question,
  // in this case, we always show if the user choses to ignore.
  prompts = prompts.reduce(function (acc, curr) {
    acc.push(curr);
    // console.log(curr.choices[0].value.vuln);
    var rule = snyk.policy.getByVuln(policy, curr.choices[0].value.vuln);
    var defaultAnswer = 'None given';
    if (rule && rule.type === 'ignore') {
      defaultAnswer = rule.reason;
    }
    acc.push({
      name: curr.name + '-reason',
      message: '[audit] Reason for ignoring vulnerability?',
      default: defaultAnswer,
      when: function (answers) {
        if (!answers[curr.name]) {
          return false;
        }
        return answers[curr.name].choice === 'ignore';
      },
    });
    return acc;
  }, []);

  return prompts;
}

function startOver() {
  return {
    name: 'misc-start-over',
    message: 'Do you want to revisit your existing policy [y] or only update ' +
      'it [N]?',
    type: 'confirm',
    default: false,
  };
}

function nextSteps(pkg, prevAnswers) {
  var skipProtect = false;
  var prompts = [];
  var i;

  i = (undefsafe(pkg, 'scripts.test') || '').indexOf('snyk test');
  if (i === -1) {
    prompts.push({
      name: 'misc-add-test',
      message: 'Add `snyk test` to package.json file to fail test on newly ' +
        'disclosed vulnerabilities?',
      type: 'confirm',
      default: true,
    });
  }

  // early exit if prevAnswers is false (when snyk test.ok === true)
  if (prevAnswers === false) {
    return prompts;
  }

  i = (undefsafe(pkg, 'scripts.postinstall') || '') .indexOf('snyk pro');

  // if `snyk protect` doesn't already appear, then check if we need to add it
  if (i === -1) {
    skipProtect = Object.keys(prevAnswers).every(function (key) {
      return prevAnswers[key].choice !== 'patch';
    });
  } else {
    skipProtect = true;
  }

  if (!skipProtect) {
    prompts.push({
      name: 'misc-add-protect',
      message: 'Add `snyk protect` as package.json post-install step to apply' +
        ' chosen patches on install?',
      type: 'confirm',
      default: true,
    });
  }

  return prompts;
}