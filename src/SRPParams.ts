import { DefaultParams } from './engine/DefaultParameters';
import { SRPEngine, Hash } from "./engine/SRPEngine";

/**
 * Multiplicative group: prime number and modulo.
 */
export type SRPGroup =
    | 'rfc5054_1024'
    | 'rfc5054_1536'
    | 'rfc5054_2048'
    | 'rfc5054_3072'
    | 'rfc5054_4096'
    | 'rfc5054_6144'
    | 'rfc5054_8192'
    | { N: string, g: string };

export type SRPParams =
    | 'default'
    | 'homekit'
    | {
        group: SRPGroup,
        hash: 'sha-1' | 'sha-256' | 'sha-512' | Hash
    }

export function createSRPEngine(params: SRPParams) {

    // Default presets
    if (params === 'default') {
        return SRPEngine.create(
            DefaultParams.rfc5054_2048.N,
            DefaultParams.rfc5054_2048.g,
            'sha-256'
        );
    } else if (params === 'homekit') {
        return SRPEngine.create(
            DefaultParams.rfc5054_3072.N,
            DefaultParams.rfc5054_3072.g,
            'sha-512'
        );
    }

    // Resolve groups
    let group: { N: string, g: string };
    if (typeof params.group === 'string') {
        group = DefaultParams[params.group];
        if (!group) {
            throw Error('Unable to find named group ' + params.group);
        }
    } else {
        group = params.group;
    }

    // Create Engine
    return SRPEngine.create(
        group.N,
        group.g,
        params.hash
    );
}