<?php


namespace Klimesf\Security\DI;

use Nette;
use Nette\DI\CompilerExtension;
use Nette\Schema\Expect;

/**
 * Nette DI extension which registers JWTUserStorage.
 * @package   Klimesf\Security\DI
 * @author    Filip Klimes <filip@filipklimes.cz>
 */
class JWTUserStorageExtension extends CompilerExtension
{
	public function getConfigSchema(): Nette\Schema\Schema
	{
		return Expect::structure([
			'identitySerializer' => Expect::string('Klimesf\Security\IdentitySerializer'),
			'generateJti' => Expect::bool(true),
			'generateIat' => Expect::bool(true),
			'expiration' => Expect::string('20 days'),
			'privateKey' => Expect::string()->required(),
			'algorithm' => Expect::string()->required(),
		]);
	}

	public function loadConfiguration()
	{
		$builder = $this->getContainerBuilder();
		$config = (array) $this->getConfig();

		$builder->addDefinition($this->prefix('firebaseJWTWrapper'))
			->setType('Klimesf\Security\JWT\FirebaseJWTWrapper');

		$userStorageDefinition = $builder->addDefinition($this->prefix('jwtUserStorage'))
			->setType('Klimesf\Security\JWTUserStorage')
			->setArguments([$config['privateKey'], $config['algorithm']]);
		$userStorageDefinition->addSetup('setGenerateIat', [$config['generateIat']]);
		$userStorageDefinition->addSetup('setGenerateJti', [$config['generateJti']]);

		// If expiration date is set, add service setup
		if ($config['expiration']) {
			$userStorageDefinition->addSetup('setExpiration', [$config['expiration']]);
		}

		$builder->addDefinition($this->prefix('identitySerializer'))
			->setType($config['identitySerializer']);

		// Disable Nette's default IUserStorage implementation
		$builder->getDefinition('security.userStorage')->setAutowired(false);
	}
}
