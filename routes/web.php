<?php

use App\Http\Controllers\dashboard\ProjectController;
use App\Http\Controllers\dashboard\TaskController;
use App\Http\Controllers\dashboard\UsersController;
use Illuminate\Support\Facades\Route;


/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Route::get('/dashboard', function () {
    return view('dashboard');
})->middleware(['auth', 'verified'])->name('dashboard');
require __DIR__.'/auth.php';


Route::get('change/tenant/{currentTenantId}', [\App\Http\Controllers\dashboard\TenantController::class ,'changeTenant'])->name('change.tenant');
Route::get('accept/invitation{token}' ,[UsersController::class,'accept_invitation'])->name('accept.invitation');

// route resource

Route::resource('projects' , ProjectController::class);
Route::resource('tasks' , TaskController::class);
Route::resource('users' , UsersController::class)->middleware('can:users_mangers');

