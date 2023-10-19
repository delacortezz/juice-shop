/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import fs from 'fs'
import yaml from 'js-yaml'
import { getCodeChallenges } from '../lib/codingChallenges'
import * as accuracy from '../lib/accuracy'
import * as utils from '../lib/utils'

const challengeUtils = require('../lib/challengeUtils')

interface SnippetRequestBody {
  challenge: string
}

interface VerdictRequestBody {
  selectedLines: number[]
  key: string
}

const setStatusCode = (error: any) => {
  switch (error.name) {
    case 'BrokenBoundary':
      return 422
    default:
      return 200
  }
}

export const retrieveCodeSnippet = async (challengeKey: string) => {
  const codeChallenges = await getCodeChallenges()
  if (codeChallenges.has(challengeKey)) {
    return codeChallenges.get(challengeKey) ?? null
  }
  return null
}

exports.serveCodeSnippet = () => async (req: Request<SnippetRequestBody, Record<string, unknown>, Record<string, unknown>>, res: Response, next: NextFunction) => {
  try {
    const snippetData = await retrieveCodeSnippet(req.params.challenge)
    if (snippetData == null) {
      res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${req.params.challenge}` })
      return
    }
    res.status(200).json({ snippet: snippetData.snippet })
  } catch (error) {
    const statusCode = setStatusCode(error)
    res.status(statusCode).json({ status: 'error', error: utils.getErrorMessage(error) })
  }
}

export const retrieveChallengesWithCodeSnippet = async () => {
  const codeChallenges = await getCodeChallenges()
  return [...codeChallenges.keys()]
}

exports.serveChallengesWithCodeSnippet = () => async (req: Request, res: Response, next: NextFunction) => {
  const codingChallenges = await retrieveChallengesWithCodeSnippet()
  res.json({ challenges: codingChallenges })
}

export const getVerdict = (vulnLines: number[], neutralLines: number[], selectedLines: number[]) => {
  if (selectedLines === undefined) return false
  if (vulnLines.length > selectedLines.length) return false
  if (!vulnLines.every(e => selectedLines.includes(e))) return false
  const okLines = [...vulnLines, ...neutralLines]
  const notOkLines = selectedLines.filter(x => !okLines.includes(x))
  return notOkLines.length === 0
}

exports.checkVulnLines = () => async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  const key = req.body.key;
  try {
    const snippetData = await retrieveCodeSnippet(key);
    
    if (snippetData === null) {
      return res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${key}` });
    }

    const vulnLines: number[] = snippetData.vulnLines;
    const neutralLines: number[] = snippetData.neutralLines;
    const selectedLines: number[] = req.body.selectedLines;
    const verdict = getVerdict(vulnLines, neutralLines, selectedLines);

    if (verdict) {
      await challengeUtils.solveFindIt(key);
      return res.status(200).json({ verdict: true });
    } else {
      const codingChallengeInfos = await loadCodingChallengeInfos(key);
      let hint;

      if (codingChallengeInfos?.hints) {
        const attemptNumber = accuracy.getFindItAttempts(key);
        
        if (attemptNumber > codingChallengeInfos.hints.length) {
          if (vulnLines.length === 1) {
            hint = res.__('Line {{vulnLine}} is responsible for this vulnerability or security flaw. Select it and submit to proceed.', { vulnLine: vulnLines[0].toString() });
          } else {
            hint = res.__('Lines {{vulnLines}} are responsible for this vulnerability or security flaw. Select them and submit to proceed.', { vulnLines: vulnLines.toString() });
          }
        } else {
          const nextHint = codingChallengeInfos.hints[attemptNumber - 1];
          
          if (nextHint) {
            hint = res.__(nextHint);
          }
        }
      }

      accuracy.storeFindItVerdict(key, false);
      return res.status(200).json({ verdict: false, hint });
    }
  } catch (error) {
    const statusCode = setStatusCode(error);
    return res.status(statusCode).json({ status: 'error', error: utils.getErrorMessage(error) });
  }
}

async function loadCodingChallengeInfos(key) {
  return new Promise((resolve, reject) => {
    fs.readFile('./data/static/codefixes/' + key + '.info.yml', 'utf8', (err, data) => {
      if (err) {
        resolve(null);
      } else {
        const codingChallengeInfos = yaml.load(data);
        resolve(codingChallengeInfos);
      }
    });
  });
}
