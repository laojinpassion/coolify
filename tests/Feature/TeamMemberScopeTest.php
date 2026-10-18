<?php

use App\Livewire\Team\Member;
use App\Models\Application;
use App\Models\Environment;
use App\Models\InstanceSettings;
use App\Models\Project;
use App\Models\Server;
use App\Models\StandaloneDocker;
use App\Models\Team;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Livewire\Livewire;

uses(RefreshDatabase::class);

beforeEach(function () {
    InstanceSettings::forceCreate(['id' => 0]);

    $this->team = Team::factory()->create();
    $this->owner = User::factory()->create();
    $this->team->members()->attach($this->owner->id, ['role' => 'owner']);

    $this->projectA = Project::factory()->create(['team_id' => $this->team->id, 'name' => 'project-a']);
    $this->projectB = Project::factory()->create(['team_id' => $this->team->id, 'name' => 'project-b']);
    $this->environmentA1 = Environment::factory()->create(['project_id' => $this->projectA->id, 'name' => 'a1']);
    $this->environmentA2 = Environment::factory()->create(['project_id' => $this->projectA->id, 'name' => 'a2']);

    $this->server = Server::factory()->create(['team_id' => $this->team->id]);
    $this->destination = StandaloneDocker::where('server_id', $this->server->id)->firstOrFail();
});

function attachScopedMember(Team $team, string $role, ?int $projectId = null, ?int $environmentId = null): User
{
    $member = User::factory()->create();

    $attributes = ['role' => $role];
    if ($projectId !== null) {
        $attributes['project_id'] = $projectId;
    }
    if ($environmentId !== null) {
        $attributes['environment_id'] = $environmentId;
    }

    $team->members()->attach($member->id, $attributes);

    return $member;
}

function scopedApplication(Environment $environment, StandaloneDocker $docker): Application
{
    return Application::factory()->create([
        'environment_id' => $environment->id,
        'destination_id' => $docker->id,
        'destination_type' => $docker->getMorphClass(),
    ]);
}

test('unrestricted members keep full access to every project and environment', function () {
    $member = attachScopedMember($this->team, 'member');

    expect($member->membershipScopeFor($this->team->id))->toBeNull()
        ->and($member->canAccessProject($this->projectA))->toBeTrue()
        ->and($member->canAccessProject($this->projectB))->toBeTrue()
        ->and($member->canAccessEnvironment($this->environmentA1))->toBeTrue()
        ->and($member->canAccessEnvironment($this->environmentA2))->toBeTrue();
});

test('a project-scoped member can only access that project', function () {
    $member = attachScopedMember($this->team, 'member', $this->projectA->id);

    expect($member->membershipScopeFor($this->team->id))->toBe(['project_id' => $this->projectA->id, 'environment_id' => null])
        ->and($member->canAccessProject($this->projectA))->toBeTrue()
        ->and($member->canAccessProject($this->projectB))->toBeFalse();
});

test('an environment-scoped member can only access that environment', function () {
    $member = attachScopedMember($this->team, 'member', $this->projectA->id, $this->environmentA1->id);

    expect($member->canAccessProject($this->projectA))->toBeTrue()
        ->and($member->canAccessEnvironment($this->environmentA1))->toBeTrue()
        ->and($member->canAccessEnvironment($this->environmentA2))->toBeFalse()
        ->and($member->canAccessProject($this->projectB))->toBeFalse();
});

test('admins are never scoped', function () {
    $admin = attachScopedMember($this->team, 'admin', $this->projectA->id);

    expect($admin->membershipScopeFor($this->team->id))->toBeNull()
        ->and($admin->canAccessProject($this->projectB))->toBeTrue();
});

test('resource policies honour the membership scope', function () {
    $member = attachScopedMember($this->team, 'member', $this->projectA->id);
    $applicationInScope = scopedApplication($this->environmentA1, $this->destination);
    $applicationOutOfScope = scopedApplication($this->environmentA2, $this->destination);

    expect($member->can('view', $applicationInScope))->toBeTrue()
        ->and($member->can('view', $applicationOutOfScope))->toBeFalse();
});

test('admins can set and clear a member scope', function () {
    $member = attachScopedMember($this->team, 'member');
    $this->actingAs($this->owner);

    Livewire::test(Member::class, ['member' => $member])
        ->call('setScope', $this->projectB->id, null);

    expect($member->refresh()->membershipScopeFor($this->team->id))
        ->toBe(['project_id' => $this->projectB->id, 'environment_id' => null])
        ->and($member->canAccessProject($this->projectA))->toBeFalse()
        ->and($member->canAccessProject($this->projectB))->toBeTrue();

    Livewire::test(Member::class, ['member' => $member])
        ->call('setScope', null, null);

    expect($member->refresh()->membershipScopeFor($this->team->id))->toBeNull();
});

test('setScope rejects scopes outside the team', function () {
    $member = attachScopedMember($this->team, 'member');
    $foreignTeam = Team::factory()->create();
    $foreignProject = Project::factory()->create(['team_id' => $foreignTeam->id]);
    $this->actingAs($this->owner);

    Livewire::test(Member::class, ['member' => $member])
        ->call('setScope', $foreignProject->id, null);

    expect($member->refresh()->membershipScopeFor($this->team->id))->toBeNull();
});

test('setScope rejects an environment outside the scoped project', function () {
    $member = attachScopedMember($this->team, 'member');
    $environmentInB = Environment::factory()->create(['project_id' => $this->projectB->id]);
    $this->actingAs($this->owner);

    Livewire::test(Member::class, ['member' => $member])
        ->call('setScope', $this->projectA->id, $environmentInB->id);

    expect($member->refresh()->membershipScopeFor($this->team->id))->toBeNull();
});

test('setScope cannot scope admins', function () {
    $admin = attachScopedMember($this->team, 'admin');
    $this->actingAs($this->owner);

    Livewire::test(Member::class, ['member' => $admin])
        ->call('setScope', $this->projectA->id, null);

    expect($admin->refresh()->membershipScopeFor($this->team->id))->toBeNull();
});

test('members cannot set scopes', function () {
    $member = attachScopedMember($this->team, 'member');
    $peer = attachScopedMember($this->team, 'member');
    $this->actingAs($member);

    Livewire::test(Member::class, ['member' => $peer])
        ->call('setScope', $this->projectA->id, null);

    expect($peer->refresh()->membershipScopeFor($this->team->id))->toBeNull();
});
