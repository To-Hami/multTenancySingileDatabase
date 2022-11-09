<?php

namespace App\Http\Controllers\dashboard;

use App\Http\Controllers\Controller;
use App\Http\Requests\storeUsersRequest;
use App\Models\Invitation;
use App\Notifications\sendInvitaion;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;

class UsersController extends Controller
{
    public function index()
    {
        $invitations = Invitation::where('tenant_id' , auth()->user()->current_tenant_id)->latest()->get();
        return view('dashboard.users.index',compact('invitations'));
    }

    public  function store(storeUsersRequest $request ){

    $invitation =   Invitation::create([
          'email'=> $request->email,
          'token'=>Str::random(32),
          'tenant_id'=> auth()->user()->current_tenant_id
      ]);

      Notification::route('mail',$request->email)->notify( new sendInvitaion($invitation));

      return redirect()->back();
    }

    public function accept_invitation($token){
        $invitation = Invitation::with('tenant')->
                    whereToken($token)->
                    whereNull('excepted_at')->
                    firstOrFail();

        if(auth()->check()){
            $invitation->update(['excepted_at' => now()]);
             auth()->user()->tenants()->attach($invitation->tenant_id);
             auth()->user()->update(['current_tenant_id' , $invitation->tenant_id]);
            return  redirect()->route('dashboard');
        }else{
           return redirect()->route('register',['token' => $invitation->token]);
        }
    }
}
