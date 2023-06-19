/* eslint-disable @typescript-eslint/no-use-before-define */
// This example demonstrates a NodeJS 8.10 async handler[1], however of course you could use
// the more traditional callback-style handler.

import { validateOwToken } from '@firestone-hs/aws-lambda-utils';
import { SecretsManager } from 'aws-sdk';
import { GetSecretValueRequest, GetSecretValueResponse } from 'aws-sdk/clients/secretsmanager';
import { sign } from 'jsonwebtoken';
import fetch from 'node-fetch';

const secretsManager = new SecretsManager({ region: 'us-west-2' });

// [1]: https://aws.amazon.com/blogs/compute/node-js-8-10-runtime-now-available-in-aws-lambda/
export default async (event): Promise<any> => {
	const headers = {
		'Access-Control-Allow-Headers':
			'Accept,Accept-Language,Content-Language,Content-Type,Authorization,x-correlation-id,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
		'Access-Control-Allow-Methods': 'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT',
		'Access-Control-Allow-Origin': event.headers.Origin || event.headers.origin || '*',
	};

	// Preflight
	if (!event.body) {
		const response = {
			statusCode: 200,
			body: null,
			headers: headers,
		};
		return response;
	}

	const body = JSON.parse(event.body);
	const owToken = body.owToken;
	const validationResult = await validateOwToken(owToken);
	if (!validationResult?.username) {
		const response = {
			statusCode: 403,
			body: null,
			headers: headers,
		};
		return response;
	}

	// Token is valid, create a Firestone token
	const secretRequest: GetSecretValueRequest = {
		SecretId: 'sso',
	};
	const secret: SecretInfo = await getSecret(secretRequest);

	// Generate a jwt token that can be used for subsequent calls
	const userDetails: UserDetails = {
		userName: validationResult.username,
	};
	const fsToken = generateJwtToken(userDetails, secret.fsJwtTokenKey);
	const response = {
		statusCode: 200,
		body: JSON.stringify({ fsToken: fsToken }),
		headers: headers,
	};
	return response;
};

const generateJwtToken = (userDetails: UserDetails, secret: string): string => {
	// Generate a JWT token
	return sign(
		{
			...userDetails,
			sub: userDetails.userName,
		},
		secret,
		{
			expiresIn: '5d',
			algorithm: 'HS256',
		},
	);
};

const getSecret = (secretRequest: GetSecretValueRequest) => {
	return new Promise<SecretInfo>((resolve) => {
		secretsManager.getSecretValue(secretRequest, (err, data: GetSecretValueResponse) => {
			const secretInfo: SecretInfo = JSON.parse(data.SecretString);
			resolve(secretInfo);
		});
	});
};

interface SecretInfo {
	readonly clientId: string;
	readonly clientSecret: string;
	readonly fsJwtTokenKey: string;
}

interface UserDetails {
	readonly userName: string;
}
