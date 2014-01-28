<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use Miny\Application\BaseApplication;

class Module extends \Miny\Modules\Module
{

    public function defaultConfiguration()
    {
        return array(
            'oauth' => array(
                'request_data' => '&request->get',
                'request_path' => '&request->path'
            )
        );
    }

    public function init(BaseApplication $app)
    {
        $app->getFactory()->add('oauth', __NAMESPACE__ . '\OAuthWrapper')
                ->setArguments('@oauth:request_data', '@oauth:request_path', '&log');
    }
}