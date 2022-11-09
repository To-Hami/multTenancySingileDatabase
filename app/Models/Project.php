<?php

namespace App\Models;

use App\Traits\FilterByUser;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Project extends Model
{

    use HasFactory ;
    use FilterByUser ;

    protected $guarded = [];

    /**************************  relations  *****************************/

    public function tasks()
    {
        return $this->hasMany(Task::class);
    }

    /**************************** functions  ***********************************/

    /* use in trait fillter by user

    protected static function boot()
    {
        parent::boot();
  // event creating
        self::creating(function ($model) {
            $model->user_id = auth()->id();
        });


  // add global scope
        self::addGlobalScope(function (Builder $builder) {
            $builder->where('user_id', auth()->id());
        });
    }

    */
}
