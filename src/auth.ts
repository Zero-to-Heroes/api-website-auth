/* eslint-disable @typescript-eslint/camelcase */
/* eslint-disable @typescript-eslint/no-use-before-define */
// This example demonstrates a NodeJS 8.10 async handler[1], however of course you could use
// the more traditional callback-style handler.

import { getConnection } from '@firestone-hs/aws-lambda-utils';
import { SecretsManager } from 'aws-sdk';
import { GetSecretValueRequest, GetSecretValueResponse } from 'aws-sdk/clients/secretsmanager';
import { decode, JwtPayload } from 'jsonwebtoken';
import fetch from 'node-fetch';
import SqlString from 'sqlstring';
import { URLSearchParams } from 'url';
import { AuthInfo } from './model';

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
	const code = body.authCode;
	console.log('processing event 2', code, body);

	const secretRequest: GetSecretValueRequest = {
		SecretId: 'sso',
	};
	const secret: SecretInfo = await getSecret(secretRequest);
	console.log('got secret', secret);

	const redirect = body.dev ? 'http://localhost:4200' : 'https://www.firestoneapp.gg';
	console.log('redirect url', redirect);

	const params = new URLSearchParams();
	params.append('client_id', secret.clientId);
	params.append('client_secret', secret.clientSecret);
	params.append('grant_type', 'authorization_code');
	params.append('code', code);
	params.append('redirect_uri', `${redirect}/owAuth`);
	const authResponse = await fetch('https://accounts.overwolf.com/oauth2/token', {
		method: 'post',
		body: params,
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
	});
	const authResult = await authResponse.json();
	console.debug('authResult', authResult);

	if (authResult.error) {
		const stringResults = JSON.stringify({
			userName: null,
			premium: false,
			valid: false,
		});
		const response = {
			statusCode: 200,
			body: stringResults,
			headers: headers,
		};
		return response;
	}

	const decodedJwt: JwtPayload = decode(authResult.access_token) as JwtPayload;
	console.log('decodedJwt', decodedJwt);

	const mysql = await getConnection();
	const queryResult = await mysql.query(`
		SELECT isPremium FROM user_mapping 
		WHERE userName = ${SqlString.escape(decodedJwt.sub)}
		LIMIT 1
	`);
	const isPremium = decodedJwt.sub === 'daedin' ? true : !!queryResult[0] ? queryResult[0].isPremium === 1 : false;
	console.debug('isPremium', isPremium, queryResult);

	const result: AuthInfo = {
		userName: decodedJwt.sub,
		issuedAt: decodedJwt.iat,
		expiration: decodedJwt.exp,
		premium: isPremium,
		valid: true,
	};
	const stringResults = JSON.stringify(result);
	const response = {
		statusCode: 200,
		body: stringResults,
		headers: headers,
	};
	return response;
};

const getSecret = (secretRequest: GetSecretValueRequest) => {
	return new Promise<SecretInfo>(resolve => {
		secretsManager.getSecretValue(secretRequest, (err, data: GetSecretValueResponse) => {
			const secretInfo: SecretInfo = JSON.parse(data.SecretString);
			resolve(secretInfo);
		});
	});
};

interface SecretInfo {
	readonly clientId: string;
	readonly clientSecret: string;
}
