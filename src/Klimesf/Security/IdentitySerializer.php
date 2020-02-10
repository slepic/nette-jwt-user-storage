<?php

declare(strict_types=1);

namespace Klimesf\Security;

use Nette\Security\Identity;
use Nette\Security\IIdentity;

/**
 * @package   Klimesf\Security
 * @author    Filip Klimes <filip@filipklimes.cz>
 * @copyright 2015, Startupedia s.r.o.
 */
class IdentitySerializer implements IIdentitySerializer
{

	/**
	 * Serializes the IIdentity into an array, which will then be stored in
	 * the JWT access token.
	 * @param IIdentity $identity
	 * @return array
	 */
	public function serialize(IIdentity $identity): array
	{
		return [
			'sub' => $identity->getId(),
			'roles' => $identity->getRoles(),
		];
	}


	/**
	 * Deserializes the identity data from an array contained in the JWT and
	 * loads into into IIdentity.
	 * @param array $jwtData
	 * @return IIdentity|null
	 */
	public function deserialize($jwtData): ?IIdentity
	{
		return array_key_exists('sub', $jwtData) && array_key_exists('roles', $jwtData)
			? new Identity($jwtData['sub'], $jwtData['roles'])
			: null;
	}
}
