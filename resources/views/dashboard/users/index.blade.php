<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 leading-tight">
            {{ __('Users') }}
        </h2>
    </x-slot>

    <div class="py-12">
        <div class="max-w-7xl mx-auto sm:px-6 lg:px-8">
            <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg">
                <div class="p-6 bg-white border-b border-gray-200">


                    <form method="POST" action="{{ route('users.store') }}">
                    @csrf
                    @method('post')

                        <!-- Email Address -->
                        <div class="mt-4">
                            <x-input-label for="email" :value="__('Email')"/>

                            <x-text-input id="email" class="block mt-1 w-full" type="email" name="email"
                                          :value="old('email')" required/>

                            <x-input-error :messages="$errors->get('email')" class="mt-2"/>
                        </div>

                        <div class="flex my-4">

                            <x-primary-button class="">
                                {{ __('Send Invitation') }}
                            </x-primary-button>
                        </div>
                    </form>


                    <table class="w-full text-sm text-left text-gray-500 dark:text-gray-400">
                        <thead class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-700 dark:text-gray-400">
                        <tr>
                            <th scope="col" class="px-6 py-3 text-left">
                                Email
                            </th>
                            <th scope="col" class="px-6 py-3 text-left">
                                Send on
                            </th>

                        </tr>
                        </thead>
                        <tbody>
                        @forelse ($invitations as $invitation)
                            <tr class="bg-white border-b dark:bg-gray-800 dark:border-gray-700">
                                <td class="px-6 py-4 font-medium text-gray-900 dark:text-white whitespace-nowrap">
                                    {{ $invitation->email }}
                                </td>
                                <td class="px-6 py-4 font-medium text-gray-900 dark:text-white whitespace-nowrap">
                                    {{ $invitation->created_at }}
                                </td>

                            </tr>
                        @empty
                            <tr class="bg-white border-b dark:bg-gray-800 dark:border-gray-700">
                                <td colspan="2"
                                    class="px-6 py-4 font-medium text-gray-900 dark:text-white whitespace-nowrap">
                                    {{ __('No projects found') }}
                                </td>
                            </tr>
                        @endforelse
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
