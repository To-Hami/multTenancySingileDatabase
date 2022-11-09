<?php

namespace App\Http\Controllers\dashboard;

use App\Http\Controllers\Controller;
use App\Http\Requests\storeProjectRequest;
use App\Traits\filterByUser;
use Illuminate\Http\Request;
use SebastianBergmann\CodeCoverage\Report\Xml\Project;



class ProjectController extends Controller
{


    public  function  index (){
       // $projects = \App\Models\Project::where('user_id', auth()->id())->get();
        $projects = \App\Models\Project::all();
        return view('dashboard.projects.index',compact('projects'));
    }

    public  function  create (){
        return view('dashboard.projects.create');
    }

    public function store(storeProjectRequest $request){
     \App\Models\Project::create($request->validated()
         //+ ['user_id' => auth()->id()]
        );
     return redirect()->route('projects.index');
    }

    public function edit(  \App\Models\Project $project){
        return view('dashboard.projects.edit',compact('project'));
    }

    public function update( storeProjectRequest $request , \App\Models\Project $project){
        $project->update($request->validated());
        return redirect()->route('projects.index');
    }

    public function destroy(\App\Models\Project $project){
        $project->delete();
        return redirect()->route('projects.index');
    }
}
