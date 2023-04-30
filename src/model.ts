export interface AuthInfo {
	readonly valid: boolean;
	readonly premium: boolean;
	readonly userName: string;
	readonly issuedAt: number;
	readonly expiration: number;
}
