import { isLocalFolder } from '../../../../lib/detect';
import {
  IaCTestFlags,
  IacFileParsed,
  IacFileParseFailure,
  SafeAnalyticsOutput,
  TestReturnValue,
  EngineType,
} from './types';
import { addIacAnalytics } from './analytics';
import { TestResult } from '../../../../lib/snyk-test/legacy';
import {
  initLocalCache,
  loadFiles,
  parseFiles,
  scanFiles,
  getIacOrgSettings,
  applyCustomSeverities,
  formatScanResults,
  cleanLocalCache,
} from './measurable-methods';
import { isFeatureFlagSupportedForOrg } from '../../../../lib/feature-flags';
import { FlagError } from './assert-iac-options-flag';

// this method executes the local processing engine and then formats the results to adapt with the CLI output.
// this flow is the default GA flow for IAC scanning.
export async function test(
  pathToScan: string,
  options: IaCTestFlags,
): Promise<TestReturnValue> {
  // TODO: This should support the --org flag and related env variables.
  const iacOrgSettings = await getIacOrgSettings();
  const customRules = await customRulesPathForOrg(
    options.customRules,
    iacOrgSettings.meta.org,
  );

  await initLocalCache({ customRules });

  const filesToParse = await loadFiles(pathToScan, options);
  const { parsedFiles, failedFiles } = await parseFiles(filesToParse, options);

  let updatedParsedFiles = parsedFiles;
  if (customRules) {
    updatedParsedFiles = parsedFiles.map((file) => ({
      ...file,
      engineType: EngineType.Custom,
    }));
  }

  const scannedFiles = await scanFiles(updatedParsedFiles);
  const resultsWithCustomSeverities = await applyCustomSeverities(
    scannedFiles,
    iacOrgSettings.customPolicies,
  );
  const formattedResults = formatScanResults(
    resultsWithCustomSeverities,
    options,
    iacOrgSettings.meta,
  );
  addIacAnalytics(formattedResults);
  cleanLocalCache();

  // TODO: add support for proper typing of old TestResult interface.
  return {
    results: (formattedResults as unknown) as TestResult[],
    // NOTE: No file or parsed file data should leave this function.
    failures: isLocalFolder(pathToScan)
      ? failedFiles.map(removeFileContent)
      : undefined,
  };
}

async function customRulesPathForOrg(
  customRules: string | undefined,
  org: string,
): Promise<string | undefined> {
  if (!customRules) return;

  const isCustomRulesSupported =
    (await isFeatureFlagSupportedForOrg('iacCustomRules', org)).ok === true;
  if (isCustomRulesSupported) {
    return customRules;
  }

  throw new FlagError('customRules');
}

export function removeFileContent({
  filePath,
  fileType,
  failureReason,
  projectType,
}: IacFileParsed | IacFileParseFailure): SafeAnalyticsOutput {
  return {
    filePath,
    fileType,
    failureReason,
    projectType,
  };
}
