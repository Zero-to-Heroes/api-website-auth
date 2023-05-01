export interface AuthInfo {
	readonly premium: boolean;
	readonly userName: string;
	readonly preferredUsername: string;
	readonly nickname: string;
	readonly picture: string;
	readonly valid: boolean;
	readonly issuedAt: number;
	readonly expiration: number;
	readonly fsToken: string;
}
