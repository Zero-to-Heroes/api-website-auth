/* eslint-disable @typescript-eslint/no-use-before-define */
// This example demonstrates a NodeJS 8.10 async handler[1], however of course you could use
// the more traditional callback-style handler.

import { getConnection } from '@firestone-hs/aws-lambda-utils';
import { SecretsManager } from 'aws-sdk';
import { GetSecretValueRequest, GetSecretValueResponse } from 'aws-sdk/clients/secretsmanager';
import { JwtPayload, decode, sign } from 'jsonwebtoken';
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
	// console.log('processing event 2', code, body);

	const secretRequest: GetSecretValueRequest = {
		SecretId: 'sso',
	};
	const secret: SecretInfo = await getSecret(secretRequest);
	// console.log('got secret', secret);

	const redirect = body.dev ? 'http://localhost:4200' : 'https://www.firestoneapp.gg';
	// console.log('redirect url', redirect);

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
	const authResult: any = await authResponse.json();
	// console.debug('authResult', authResult);

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

	const decodedIdToken: JwtPayload & {
		nickname: string;
		picture: string;
		preferred_username: string;
	} = decode(authResult.id_token) as any;
	// console.log('decodedIdToken', decodedIdToken);

	const mysql = await getConnection();
	const queryResult = await mysql.query(`
		SELECT isPremium FROM user_mapping 
		WHERE userName = ${SqlString.escape(decodedIdToken.sub)}
		LIMIT 1
	`);
	await mysql.end();
	const isPremium = decodedIdToken.sub === 'daedin' ? true : queryResult[0] ? queryResult[0].isPremium === 1 : false;
	// console.debug('isPremium', isPremium, queryResult);

	// Generate a jxt token that can be used for subsequent calls
	const userDetails: UserDetails = {
		userName: decodedIdToken.sub,
		preferredUsername: decodedIdToken.preferred_username,
		nickname: decodedIdToken.nickname,
		picture: decodedIdToken.picture,
	};
	const fsToken = generateJwtToken(userDetails, secret.fsJwtTokenKey);
	const decodedFsTken: JwtPayload = decode(fsToken) as JwtPayload;

	const result: AuthInfo = {
		...userDetails,
		issuedAt: decodedFsTken.iat,
		expiration: decodedFsTken.exp,
		premium: isPremium,
		valid: true,
		fsToken: fsToken,
	};
	const stringResults = JSON.stringify(result);
	const response = {
		statusCode: 200,
		body: stringResults,
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
	readonly preferredUsername: string;
	readonly nickname: string;
	readonly picture: string;
}
