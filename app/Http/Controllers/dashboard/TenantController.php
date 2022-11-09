<?php

namespace App\Http\Controllers\dashboard;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class TenantController extends Controller
{
    public function changeTenant($currentTenantId)
    {
        //check user
        /*
               if( auth()->user()->tenants()->where('id' , $currentTenantId )->doesntExist()){
                   abort(404);
               }
        */

        $tenant = auth()->user()->tenants()->findOrFail($currentTenantId);
        auth()->user()->update(['current_tenant_id' => $currentTenantId]);
        return redirect()->route('dashboard');

    }
}
