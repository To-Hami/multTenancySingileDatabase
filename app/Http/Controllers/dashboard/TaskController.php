<?php

namespace App\Http\Controllers\dashboard;

use App\Http\Controllers\Controller;
use App\Http\Requests\storetaskRequest;
use function Symfony\Component\String\width;

class TaskController extends Controller
{
    public  function  index (){
        $tasks = \App\Models\Task::all();
        return view('dashboard.tasks.index',compact('tasks'));
    }

    public  function  create (){
        $projects = \App\Models\Project::all();
        return view('dashboard.tasks.create' , compact('projects'));
    }

    public function store(storeTaskRequest $request){
        \App\Models\Task::create($request->validated());
        return redirect()->route('tasks.index');
    }

    public function edit(  \App\Models\Task $task ){
        $projects = \App\Models\Project::all();
        return view('dashboard.tasks.edit',compact('projects','task'));
    }

    public function update( storetaskRequest $request , \App\Models\Task $task){
        $task->update($request->validated());
        return redirect()->route('tasks.index');
    }

    public function destroy(\App\Models\Task $task){
        $task->delete();
        return redirect()->route('tasks.index');
    }
}
