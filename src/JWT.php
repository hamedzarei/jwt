<?php
/**
 * Created by PhpStorm.
 * User: zrhm7232
 * Date: 3/2/18
 * Time: 11:48 PM
 */

namespace Zrhm7232\Jwt;


class JWT
{
    /*
     * time to live for expiration
     * if want no expiration set -1
     */
    public $ttl = -1;

    public $private_keygen_path;

    public $keygen_pass_phrase = "zrhm7232";

    public function __construct()
    {
        $this->private_keygen_path = dirname(__FILE__)."/rsa_pass.prv";
    }

    private function createDefaultClaim($tid) {
        if (!$tid) {
            $tid = uniqid('id_', true);
        }
        $now = time();
        $checkers = [
            'nbf',
            'iat'
        ];
        $claims = [
            'nbf'     => $now,        // Not before
            'iat'     => $now,        // Issued at
            'tid'     => $tid
        ];

        if ($this->ttl != -1) {
            $claims = array_merge($claims, [
                'exp' => $now + $this->ttl*60*60, // Expires at
            ]);
            $checkers = array_merge($checkers, ['exp']);
        }


        return [
            'claims' => $claims,
            'checkers' => $checkers
        ];
    }

    public function createToken($custom_claims = [], $tid=null)
    {
        $key = \Jose\Factory\JWKFactory::createFromKeyFile(
            $this->private_keygen_path,
            $this->keygen_pass_phrase,
            [
                'alg' => 'RS256',
                'use' => 'sig',
            ]
        );

        // We want to sign the following claims
        $claims = self::createDefaultClaim($tid)['claims'];
        $claims = array_merge($claims, $custom_claims);

        // We have to create a JWS class using the JWSFactory.
        // The payload of this object contains our claims.
        $jws = \Jose\Factory\JWSFactory::createJWS($claims);

        // We add information to create the first signature
        $jws = $jws->addSignatureInformation(
            $key,
            [
                'alg' => 'RS256',
            ]
        );

        // We create a Signer object with the signature algorithms we want to use
        $signer = \Jose\Signer::createSigner(['RS256']);

        // Then we sign
        $signer->sign($jws);

        $jws = $jws->toCompactJSON(0);

        return [
            'data' => $jws
        ];
    }

    public function checkToken($input)
    {
        $key = \Jose\Factory\JWKFactory::createFromKeyFile(
            $this->private_keygen_path,
            $this->keygen_pass_phrase,
            [
                'alg' => 'RS256',
                'use' => 'sig',
            ]
        );

        $claim_checker_list = self::createDefaultClaim(null)['checkers'];
        $header_checker_list = [];

        $checker_manager = \Jose\Factory\CheckerManagerFactory::createClaimCheckerManager($claim_checker_list, $header_checker_list);

        $loader = new \Jose\Loader();
        try {
            $jws_raw = $loader->loadAndVerifySignatureUsingKey(
                $input,
                $key,
                ['RS256'],
                $signature_index
            );
        } catch (\InvalidArgumentException $ex) {
            return [
                'status' => false,
                'type' => 1,
                'message' => $ex->getMessage()
            ];
        }

        if (\Illuminate\Support\Facades\Cache::has('invalid_'.$input)) {
            $invalid = \Illuminate\Support\Facades\Cache::get('invalid_'.$input);
            if ($invalid) {
                return [
                    'status' => false,
                    'type' => 2,
                    'message' => 'token is invalid'
                ];
            }
        }

        if (\Illuminate\Support\Facades\Cache::has('refresh_'.$input)) {
            $invalid = \Illuminate\Support\Facades\Cache::get('refresh_'.$input);
            if ($invalid) {
                return [
                    'status' => false,
                    'type' => 3,
                    'message' => 'token is invalid'
                ];
            }
        }

        try {
            $checker_manager->checkJWS($jws_raw, $signature_index);
        } catch (\InvalidArgumentException $ex) {
            return [
                'status' => false,
                'type' => 0,
                'message' => $ex->getMessage()
            ];
        }


        return [
            'status' => true,
            'claims' => $jws_raw->getClaims()
        ];
    }

    public function invalidateToken($input)
    {
        \Illuminate\Support\Facades\Cache::forever('invalid_'.$input, true);

        return [
            'status' => true,
            'message' => 'successfully invalidated'
        ];
    }

    public function refreshToken($input)
    {
        $check = self::checkToken($input);
        $default_claims = self::createDefaultClaim(null)['claims'];
        if ($check['status']) {
            $tid = $check['claims']['tid'];
            $custom_claims = array_diff_key($check['claims'], $default_claims);
            $token = self::createToken($custom_claims, $tid);
        }
        else {
            $type = $check['type'];
            if ($type==0) {
                $tid = self::getInvalidateTokenClaims($input)['tid'];
                $custom_claims = array_diff_key(self::getInvalidateTokenClaims($input), $default_claims);
                $token = self::createToken($custom_claims, $tid);
            }
            else {
                return [
                    'status' => false,
                    'message' => 'must sign-in again'
                ];
            }
        }
        \Illuminate\Support\Facades\Cache::forever('refresh_'.$input, true);
        return [
            'status' => true,
            'token' => $token
        ];


    }

    private function getInvalidateTokenClaims($input)
    {
        $key = \Jose\Factory\JWKFactory::createFromKeyFile(
            $this->private_keygen_path,
            $this->keygen_pass_phrase,
            [
                'alg' => 'RS256',
                'use' => 'sig',
            ]
        );

        $loader = new \Jose\Loader();

        $jws_raw = $loader->loadAndVerifySignatureUsingKey(
            $input,
            $key,
            ['RS256'],
            $signature_index
        );

        return $jws_raw->getClaims();
    }

}