<?php

declare(strict_types=1);

namespace Klimesf\Security;

use Firebase\JWT\ExpiredException;
use Klimesf\Security\JWT\IJsonWebTokenService;
use Nette\Http\IRequest;
use Nette\Http\IResponse;
use Nette\Security\IIdentity;
use Nette\Security\IUserStorage;
use Nette\Utils\DateTime;
use Nette\Utils\Random;

/**
 * @package   Klimesf\Security
 * @author    Filip Klimes <filip@filipklimes.cz>
 */
class JWTUserStorage implements IUserStorage
{
	/**
	 * Name of the JWT access token cookie.
	 * @deprecated The constant is deprecated in favour of instance property $cookieName
	 */
	const COOKIE_NAME = 'jwt_access_token';

	/**
	 * @var IRequest
	 */
	private $request;

	/**
	 * @var IResponse
	 */
	private $response;

	/**
	 * @var IJsonWebTokenService
	 */
	private $jwtService;

	/**
	 * @var string
	 */
	private $privateKey;

	/**
	 * @var string
	 */
	private $algorithm;

	/**
	 * @var boolean
	 */
	private $generateJti = true;

	/**
	 * @var boolean
	 */
	private $generateIat = true;

	/**
	 * @var array
	 */
	private $jwtData = array();

	/**
	 * @var string|null
	 */
	private $expirationTime;

	/**
	 * @var int|null
	 */
	private $logoutReason;

	/**
	 * @var IIdentitySerializer
	 */
	private $identitySerializer;

	/**
	 * @var string|null
	 */
	private $cookiePath;

	/**
	 * @var string|null
	 */
	private $cookieDomain;

	/**
	 * @var bool|null
	 */
	private $cookieSecure;

	/**
	 * @var bool|null
	 */
	private $cookieHttpOnly;

	/**
	 * @var string
	 */
	private $cookieName;

	/**
	 * @var IIdentity|null
	 */
	private $identity;

	/**
	 * @var bool
	 */
	private $isLoaded = false;

	public function __construct(
		string $privateKey,
		string $algorithm,
		IRequest $request,
		IResponse $response,
		IJsonWebTokenService $jsonWebTokenService,
		IIdentitySerializer $identitySerializer,
		?string $cookiePath = null,
		?string $cookieDomain = null,
		?bool $cookieSecure = null,
		?bool $cookieHttpOnly = null,
		?string $cookieName = null
	) {
		$this->privateKey = $privateKey;
		$this->algorithm = $algorithm;
		$this->request = $request;
		$this->response = $response;
		$this->jwtService = $jsonWebTokenService;
		$this->identitySerializer = $identitySerializer;
		$this->cookiePath = $cookiePath;
		$this->cookieDomain = $cookieDomain;
		$this->cookieSecure = $cookieSecure;
		$this->cookieHttpOnly = $cookieHttpOnly;
		$this->cookieName = $cookieName ?: 'jwt_access_token';
	}

	public function setGenerateJti(bool $generateJti): void
	{
		$this->generateJti = $generateJti;
	}

	public function setGenerateIat(bool $generateIat): void
	{
		$this->generateIat = $generateIat;
	}

	public function setAuthenticated(bool $state): self
	{
		$this->loadJWTCookie();
		$this->jwtData['is_authenticated'] = $state;
		if (!$state) {
			$this->logoutReason = self::MANUAL;
		}
		$this->saveJWTCookie();
		return $this;
	}

	public function isAuthenticated(): bool
	{
		$this->loadJWTCookie();
		return array_key_exists('is_authenticated', $this->jwtData) ? $this->jwtData['is_authenticated'] : false;
	}

	public function setIdentity(IIdentity $identity = null): self
	{
		$this->loadJWTCookie();
		if (!$identity) {
			$this->jwtData = ['is_authenticated' => false];
		} else {
			$this->jwtData = array_merge($this->jwtData, $this->identitySerializer->serialize($identity));
			$this->identity = $identity;
			$this->saveJWTCookie();
		}
		return $this;
	}

	public function getIdentity(): ?IIdentity
	{
		$this->loadJWTCookie();
		if ($this->identity) {
			return $this->identity;
		}
		return empty($this->jwtData) ? null : $this->identitySerializer->deserialize($this->jwtData);
	}

	public function setExpiration(?string $time, int $flags = 0): self
	{
		$this->loadJWTCookie();
		$this->expirationTime = $time;
		if ($time) {
			$time = DateTime::from($time)->format('U');
			$this->jwtData['exp'] = $time;
		} else {
			unset($this->jwtData['exp']);
		}
		$this->saveJWTCookie();
		return $this;
	}

	public function getLogoutReason(): ?int
	{
		$this->loadJWTCookie();
		return $this->logoutReason;
	}

	/**
	 * Saves the JWT Access Token into HTTP cookie.
	 */
	private function saveJWTCookie(): void
	{
		if (!$this->isLoaded) {
			throw new \Exception("Invalid call of saveJWTCookie. First must be called loadJWTCookie");
		}

		if (empty($this->jwtData)) {
			$this->response->deleteCookie($this->cookieName, $this->cookiePath, $this->cookieDomain, $this->cookieSecure);
			return;
		}

		if ($this->generateIat) {
			$this->jwtData['iat'] = DateTime::from('NOW')->format('U');
		}

		unset($this->jwtData['jti']);
		if ($this->generateJti) {
			$this->jwtData['jti'] = hash('sha256', serialize($this->jwtData) . Random::generate(10));
		}

		// Encode the JWT and set the cookie
		$jwt = $this->jwtService->encode($this->jwtData, $this->privateKey, $this->algorithm);
		$this->response->setCookie($this->cookieName, $jwt, $this->expirationTime ?? 0, $this->cookiePath, $this->cookieDomain, $this->cookieSecure, $this->cookieHttpOnly);
	}

	/**
	 * Loads JWT from HTTP cookie and stores the data into the $jwtData variable.
	 */
	private function loadJWTCookie(): void
	{
		if ($this->isLoaded) {
			return;
		}
		$this->isLoaded = true;

		$jwtCookie = $this->request->getCookie($this->cookieName);
		if (!$jwtCookie) {
			$this->logoutReason = self::INACTIVITY;
			return;
		}

		try {
			$this->jwtData = (array) $this->jwtService->decode($jwtCookie, $this->privateKey, [$this->algorithm]);
		} catch (ExpiredException $e) {
			$this->logoutReason = self::INACTIVITY;
		}
	}
}
