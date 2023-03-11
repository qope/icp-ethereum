import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';

export interface _SERVICE {
  'public_key' : ActorMethod<
    [],
    { 'Ok' : { 'public_key_hex' : string } } |
      { 'Err' : string }
  >,
  'sign' : ActorMethod<
    [string],
    { 'Ok' : { 'signature_hex' : string } } |
      { 'Err' : string }
  >,
  'verify' : ActorMethod<
    [string, string, string],
    { 'Ok' : { 'is_signature_valid' : boolean } } |
      { 'Err' : string }
  >,
}
