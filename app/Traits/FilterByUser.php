<?php

namespace App\Traits;

use Illuminate\Database\Eloquent\Builder;

trait FilterByUser{

    protected static function boot()
    {
        parent::boot();

//        $currentTenantId = auth()->user()->tenants()->first()->id  ??  null;
        $currentTenantId = auth()->user()->current_tenant_id  ??  null;

// event creating
        self::creating(function ($model) use ($currentTenantId) {
            $model->user_id = auth()->id();
            $model->tenant_id =  $currentTenantId;
        });


// add global scope

        self::addGlobalScope(function (Builder $builder) {
            $builder->where('user_id', auth()->id());
        });

        self::addGlobalScope(function (Builder $builder) use($currentTenantId){
            $builder->where('tenant_id',$currentTenantId);
        });


    }

}
