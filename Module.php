<?php

/**
 * This file is part of the Miny framework.
 * (c) Dániel Buga <daniel@bugadani.hu>
 *
 * For licensing information see the LICENSE file.
 */

namespace Modules\OAuth;

use Miny\Application\Application;

class Module extends \Miny\Application\Module
{
    public function init(Application $app)
    {
        $app->add('oauth', __NAMESPACE__.'\OAuthWrapper')
            ->setArguments('&request');
    }

}
