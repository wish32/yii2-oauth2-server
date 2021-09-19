原作者没有详细的备注，令人难于使用，下面我将添加些许的备注

# yii2-oauth2-server

A wrapper for implementing an OAuth2 Server(https://github.com/bshaffer/oauth2-server-php)

## Installation

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```shell script
php composer.phar require --prefer-dist filsh/yii2-oauth2-server "*"
```

or add

```json
"filsh/yii2-oauth2-server": "^2.0"
```

to the `require` section of your composer.json.


To use this extension,  simply add the following code in your application configuration:

```php
'bootstrap' => ['oauth2'],
'modules' => [
    'oauth2' => [
        'class' => 'filsh\yii2\oauth2server\Module',
        'tokenParamName' => 'accessToken',
        'tokenAccessLifetime' => 3600 * 24,
        'storageMap' => [
            'user_credentials' => 'common\models\User',
        ],
        'grantTypes' => [
            'user_credentials' => [
                'class' => 'OAuth2\GrantType\UserCredentials',
            ],
            'refresh_token' => [
                'class' => 'OAuth2\GrantType\RefreshToken',
                'always_issue_new_refresh_token' => true
            ]
        ]
    ]
]
```

```common\models\User``` - user model implementing an interface ```\OAuth2\Storage\UserCredentialsInterface```, so the oauth2 credentials data stored in user table

The next step you should run migration

```php
yii migrate --migrationPath=@vendor/filsh/yii2-oauth2-server/src/migrations
```

this migration creates the oauth2 database scheme and insert test user credentials ```testclient:testpass``` for ```http://fake/```

add url rule to urlManager

```php
'urlManager' => [
    'rules' => [
        'POST oauth2/<action:\w+>' => 'oauth2/rest/<action>',
        ...
    ]
]
```

我的版本是这样的，在文件/backend/config/main.php （你可能是：/api/config/main.php）：
```php
'urlManager' => [
            'enablePrettyUrl' => true,
            'enableStrictParsing' => true,
            'showScriptName' => false,
            'rules' => [
                'POST oauth2/<action:\w+>' => 'oauth2/rest/<action>',
            ],
        ],
```

## Configuration

You can pass additional OAuth2 Server options by setting `options` property on the module. These options configure as the underlying OAuth2 Server also as various parts/components of [bshaffer/oauth2-server-php](https://github.com/bshaffer/oauth2-server-php).
As an example, you can configure authorization code lifetime in a response by setting `auth_code_lifetime` option.
Some of them are implemented as standalone properties on the module: `tokenParamName` => `use_jwt_access_tokens`, `tokenAccessLifetime` => `token_param_name`, `useJwtToken` => `access_lifetime`. 
Full list of options are supported by the underlying OAuth2 Server main component - [source code](https://github.com/bshaffer/oauth2-server-php/blob/5a0c8000d4763b276919e2106f54eddda6bc50fa/src/OAuth2/Server.php#L162). Options for various components spread across [bshaffer/oauth2-server-php](https://github.com/bshaffer/oauth2-server-php) source code.




# Usage

To use this extension,  simply add the behaviors for your base controller:

```php
use yii\helpers\ArrayHelper;
use yii\filters\auth\HttpBearerAuth;
use yii\filters\auth\QueryParamAuth;
use filsh\yii2\oauth2server\filters\ErrorToExceptionFilter;
use filsh\yii2\oauth2server\filters\auth\CompositeAuth;

class Controller extends \yii\rest\Controller
{
    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        return ArrayHelper::merge(parent::behaviors(), [
            'authenticator' => [
                'class' => CompositeAuth::className(),
                'authMethods' => [
                    ['class' => HttpBearerAuth::className()],
                    ['class' => QueryParamAuth::className(), 'tokenParam' => 'accessToken'],
                ]
            ],
            'exceptionFilter' => [
                'class' => ErrorToExceptionFilter::className()
            ],
        ]);
    }
}
```

以上我的做法是这样的：
创建一个文件：/common/backend/BackendController.php
```php
<?php
namespace common\backend;

use yii;
use yii\helpers\ArrayHelper;
use yii\filters\auth\HttpBearerAuth;
use yii\filters\auth\QueryParamAuth;
use filsh\yii2\oauth2server\filters\ErrorToExceptionFilter;
use filsh\yii2\oauth2server\filters\auth\CompositeAuth;
use \yii\rest\Controller;


class BackendController extends Controller
{
    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        return ArrayHelper::merge(parent::behaviors(), [
            'authenticator' => [
                'class' => CompositeAuth::className(),
                'authMethods' => [
                    ['class' => HttpBearerAuth::className()],
                    ['class' => QueryParamAuth::className(), 'tokenParam' => 'accessToken'],
                ]
            ],
            'exceptionFilter' => [
                'class' => ErrorToExceptionFilter::className()
            ],
        ]);
    }
}
```

然后，在文件/backend/controllers/SiteController.php
使你想要颁发token的类继承于\common\backend\BackendController，而不是yii\web\Controller
class SiteController extends \common\backend\BackendController
在该类SiteController里面添加一个函数（如下一步的做法，下一步是相同的，就不需要重复添加actionAuthorize()函数了）：
```php
/**
     * @return mixed
     */
    public function actionAuthorize()
    {
        if (Yii::$app->getUser()->getIsGuest())
            return $this->redirect('login');
    
        /** @var $module \filsh\yii2\oauth2server\Module */
        $module = Yii::$app->getModule('oauth2');
        $response = $module->getServer()->handleAuthorizeRequest(null, null, !Yii::$app->getUser()->getIsGuest(), Yii::$app->getUser()->getId());
    
        /** @var object $response \OAuth2\Response */
        Yii::$app->getResponse()->format = \yii\web\Response::FORMAT_JSON;
    
        return $response->getParameters();
    }
```

再然后，在/common/models/User.php
使你想保存用户数据的User model类继承于抽象类：\OAuth2\Storage\UserCredentialsInterface（同时保留原有的\yii\web\IdentityInterface）
class User extends ActiveRecord implements \yii\web\IdentityInterface,\OAuth2\Storage\UserCredentialsInterface
并在文件里面实现以下三个函数：

```php
/**
     * Implemented for Oauth2 Interface
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        /** @var \filsh\yii2\oauth2server\Module $module */
        $module = Yii::$app->getModule('oauth2');
        $token = $module->getServer()->getResourceController()->getToken();
        return !empty($token['user_id'])
        ? static::findIdentity($token['user_id'])
        : null;
    }
    
    /**
     * Implemented for Oauth2 Interface
     */
    public function checkUserCredentials($username, $password)
    {
        $user = static::findByUsername($username);
        if (empty($user)) {
            return false;
        }
        return $user->validatePassword($password);
    }
    
    /**
     * Implemented for Oauth2 Interface
     */
    public function getUserDetails($username)
    {
        $user = static::findByUsername($username);
        return ['user_id' => $user->getId()];
    }
```


此时你应该完成了，但坑还是有的，请留意


测试方法：
http://localhost/oauth2/token


Create action authorize in site controller for Authorization Code

`https://api.mysite.com/authorize?response_type=code&client_id=TestClient&redirect_uri=https://fake/`

[see more](http://bshaffer.github.io/oauth2-server-php-docs/grant-types/authorization-code/)

```php
/**
 * SiteController
 */
class SiteController extends Controller
{
    /**
     * @return mixed
     */
    public function actionAuthorize()
    {
        if (Yii::$app->getUser()->getIsGuest())
            return $this->redirect('login');
    
        /** @var $module \filsh\yii2\oauth2server\Module */
        $module = Yii::$app->getModule('oauth2');
        $response = $module->getServer()->handleAuthorizeRequest(null, null, !Yii::$app->getUser()->getIsGuest(), Yii::$app->getUser()->getId());
    
        /** @var object $response \OAuth2\Response */
        Yii::$app->getResponse()->format = \yii\web\Response::FORMAT_JSON;
    
        return $response->getParameters();
    }
}
```

Also, if you set ```allow_implicit => true``` in the ```options``` property of the module, you can use Implicit Grant Type - [see more](http://bshaffer.github.io/oauth2-server-php-docs/grant-types/implicit/)

Request example:

`https://api.mysite.com/authorize?response_type=token&client_id=TestClient&redirect_uri=https://fake/cb`

With redirect response:

`https://fake/cb#access_token=2YotnFZFEjr1zCsicMWpAA&state=xyz&token_type=bearer&expires_in=3600`
### JWT Tokens
If you want to get Json Web Token (JWT) instead of conventional token, you will need to set `'useJwtToken' => true` in module and then define two more configurations: 
`'public_key' => 'app\storage\PublicKeyStorage'` which is the class that implements [PublickKeyInterface](https://github.com/bshaffer/oauth2-server-php/blob/develop/src/OAuth2/Storage/PublicKeyInterface.php) and `'access_token' => 'OAuth2\Storage\JwtAccessToken'` which implements [JwtAccessTokenInterface.php](https://github.com/bshaffer/oauth2-server-php/blob/develop/src/OAuth2/Storage/JwtAccessTokenInterface.php)

For Oauth2 base library provides the default [access_token](https://github.com/bshaffer/oauth2-server-php/blob/develop/src/OAuth2/Storage/JwtAccessToken.php) which works great except. Just use it and everything will be fine.

and **public_key**

```php
<?php
namespace app\storage;

class PublicKeyStorage implements \OAuth2\Storage\PublicKeyInterface{


    private $pbk =  null;
    private $pvk =  null; 
    
    public function __construct()
    {
        $this->pvk =  file_get_contents('privkey.pem', true);
        $this->pbk =  file_get_contents('pubkey.pem', true); 
    }

    public function getPublicKey($client_id = null){ 
        return  $this->pbk;
    }

    public function getPrivateKey($client_id = null){ 
        return  $this->pvk;
    }

    public function getEncryptionAlgorithm($client_id = null){
        return 'RS256';
    }

}

``` 


For more, see https://github.com/bshaffer/oauth2-server-php

# Authors & Contributors
The original author of this package [Igor Maliy](https://github.com/filsh) . At the time the project maintainer is [Vardan Pogosian](https://vardan.dev).
