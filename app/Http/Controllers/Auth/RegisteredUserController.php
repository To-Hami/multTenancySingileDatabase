<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\Invitation;
use App\Models\Tenant;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules;

class RegisteredUserController extends Controller
{

    public function create()
    {
        $invitationEmail = null;

        if (request('token')) {
            $invitation = Invitation::where('token', request('token'))->firstOrFail();
            $invitationEmail = $invitation->email;
        }

        return view('auth.register', compact('invitationEmail'));
    }


    public function store(Request $request)
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['sometimes', 'string', 'email', 'max:255', 'unique:users'],
            'subdomain' => 'string|alpha|required|unique:tenants,subdomain',
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);

        $email = $request->email;
        $invitation = null;
        if (request('token')) {
            $invitation = Invitation::with('tenant')->
            where('token', request('token'))->first();
            $email = $invitation->email;

            if (!$invitation) {
                return redirect()->back()->withInput()->withErrors(['email' => __('Invitation link incorect ')]);
            }
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $email,
            'password' => Hash::make($request->password),
        ]);


        if ($invitation) {

            $invitation->update(['excepted_at' => now()]);
            $invitation->tenant->users()->attach($user->id);
            $user->update(['current_tenant_id' => $invitation->tenant_id]);
            Auth::login($user);
            return redirect(RouteServiceProvider::HOME);

        }

        $tenant = Tenant::create([
            'name' => $request->name . ' Tenant',
            'subdomain'=>$request->subdomain
        ]);
        event(new Registered($user));
        Auth::login($user);

        $tenant->users()->attach(auth()->id(), ['is_owner' => true]);
        $user->update(['current_tenant_id' => $tenant->id]);

//        return redirect(RouteServiceProvider::HOME);

        return redirect('http://' . $request->subdomain .'.' . 'localhost:8000' . RouteServiceProvider::HOME);

    }
}
