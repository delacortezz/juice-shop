/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import challengeUtils = require('../lib/challengeUtils')

import * as utils from '../lib/utils'

const reviews = require('../data/mongodb').reviews
const challenges = require('../data/datacache').challenges
const security = require('../lib/insecurity')

module.exports = function productReviews() {
  return async (req: Request, res: Response) => {
    try {
      const user = security.authenticatedUsers.from(req);

      if (user && user.data.email !== req.body.author) {

        const reviewData = {
          product: req.params.id,
          message: req.body.message,
          author: req.body.author,
          likesCount: 0,
          likedBy: [],
        };

        const review = await reviews.create(reviewData);

        res.status(201).json({ status: 'success', review });
      } else {
        res.status(403).json({ error: 'Unauthorized' });
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error));
    }
  };
};
