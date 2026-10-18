<?php

namespace App\Livewire\Team;

use App\Actions\User\RevokeUserTeamTokens;
use App\Enums\Role;
use App\Models\Environment;
use App\Models\Project;
use App\Models\User;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Livewire\Component;

class Member extends Component
{
    use AuthorizesRequests;

    public User $member;

    public function makeAdmin()
    {
        try {
            $this->authorize('manageMembers', currentTeam());

            if (Role::from(auth()->user()->role())->lt(Role::ADMIN)
                || Role::from($this->getMemberRole())->gt(auth()->user()->role())) {
                throw new \Exception('You are not authorized to perform this action.');
            }
            $teamId = currentTeam()->id;
            DB::transaction(function () use ($teamId): void {
                $this->member->teams()->updateExistingPivot($teamId, ['role' => Role::ADMIN->value]);
                RevokeUserTeamTokens::forUserTeam($this->member, $teamId);
            });
            $this->auditRoleUpdate($teamId, Role::ADMIN);
            $this->dispatch('reloadWindow');
        } catch (\Exception $e) {
            $this->dispatch('error', $e->getMessage());
        }
    }

    public function makeOwner()
    {
        try {
            $this->authorize('manageMembers', currentTeam());

            if (Role::from(auth()->user()->role())->lt(Role::OWNER)
                || Role::from($this->getMemberRole())->gt(auth()->user()->role())) {
                throw new \Exception('You are not authorized to perform this action.');
            }
            $teamId = currentTeam()->id;
            DB::transaction(function () use ($teamId): void {
                $this->member->teams()->updateExistingPivot($teamId, ['role' => Role::OWNER->value]);
                RevokeUserTeamTokens::forUserTeam($this->member, $teamId);
            });
            $this->auditRoleUpdate($teamId, Role::OWNER);
            $this->dispatch('reloadWindow');
        } catch (\Exception $e) {
            $this->dispatch('error', $e->getMessage());
        }
    }

    public function makeReadonly()
    {
        try {
            $this->authorize('manageMembers', currentTeam());

            if (Role::from(auth()->user()->role())->lt(Role::ADMIN)
                || Role::from($this->getMemberRole())->gt(auth()->user()->role())) {
                throw new \Exception('You are not authorized to perform this action.');
            }
            $teamId = currentTeam()->id;
            DB::transaction(function () use ($teamId): void {
                $this->member->teams()->updateExistingPivot($teamId, ['role' => Role::MEMBER->value]);
                RevokeUserTeamTokens::forUserTeam($this->member, $teamId);
            });
            $this->auditRoleUpdate($teamId, Role::MEMBER);
            $this->dispatch('reloadWindow');
        } catch (\Exception $e) {
            $this->dispatch('error', $e->getMessage());
        }
    }

    public function remove()
    {
        try {
            $this->authorize('manageMembers', currentTeam());

            if (Role::from(auth()->user()->role())->lt(Role::ADMIN)
                || Role::from($this->getMemberRole())->gt(auth()->user()->role())) {
                throw new \Exception('You are not authorized to perform this action.');
            }
            $teamId = currentTeam()->id;
            DB::transaction(function () use ($teamId): void {
                $this->member->teams()->detach($teamId);
                RevokeUserTeamTokens::forUserTeam($this->member, $teamId);
                $this->member->clearStoredTeamIfMatches($teamId);
            });
            auditLog('ui.team_member.removed', [
                'team_id' => $teamId,
                'member_id' => $this->member->id,
                'member_name' => $this->member->name,
                'member_email' => $this->member->email,
            ]);
            // Clear cache for the removed user - both old and new key formats
            Cache::forget("team:{$this->member->id}");
            Cache::forget("user:{$this->member->id}:team:{$teamId}");
            $this->dispatch('reloadWindow');
        } catch (\Exception $e) {
            $this->dispatch('error', $e->getMessage());
        }
    }

    public function setScope(?int $scopeProjectId = null, ?int $scopeEnvironmentId = null)
    {
        try {
            $this->authorize('manageMembers', currentTeam());

            if (Role::from(auth()->user()->role())->lt(Role::ADMIN)
                || Role::from($this->getMemberRole())->gt(auth()->user()->role())) {
                throw new \Exception('You are not authorized to perform this action.');
            }

            if (Role::from($this->getMemberRole()) !== Role::MEMBER) {
                throw new \Exception('Scopes can only be applied to members — admins and owners always have full team access.');
            }

            $teamId = currentTeam()->id;
            $projectId = $scopeProjectId !== null ? (int) $scopeProjectId : null;
            $environmentId = $scopeEnvironmentId !== null ? (int) $scopeEnvironmentId : null;

            if ($projectId !== null) {
                $projectExists = Project::where('id', $projectId)->where('team_id', $teamId)->exists();
                if (! $projectExists) {
                    throw new \Exception('The selected project does not belong to this team.');
                }

                if ($environmentId !== null) {
                    $environmentExists = Environment::where('id', $environmentId)
                        ->where('project_id', $projectId)
                        ->exists();
                    if (! $environmentExists) {
                        throw new \Exception('The selected environment does not belong to the selected project.');
                    }
                }
            } elseif ($environmentId !== null) {
                throw new \Exception('An environment scope requires a project scope.');
            }

            DB::transaction(function () use ($teamId, $projectId, $environmentId): void {
                $this->member->teams()->updateExistingPivot($teamId, [
                    'project_id' => $projectId,
                    'environment_id' => $environmentId,
                ]);
                RevokeUserTeamTokens::forUserTeam($this->member, $teamId);
            });
            auditLog('ui.team_member.scope_updated', [
                'team_id' => $teamId,
                'member_id' => $this->member->id,
                'member_name' => $this->member->name,
                'member_email' => $this->member->email,
                'project_scope' => $projectId,
                'environment_scope' => $environmentId,
            ]);
            Cache::forget("user:{$this->member->id}:team:{$teamId}");
            $this->dispatch('reloadWindow');
        } catch (\Exception $e) {
            $this->dispatch('error', $e->getMessage());
        }
    }

    private function getMemberRole()
    {
        return $this->member->teams()->where('teams.id', currentTeam()->id)->first()?->pivot?->role;
    }

    private function auditRoleUpdate(int $teamId, Role $role): void
    {
        auditLog('ui.team_member.role_updated', [
            'team_id' => $teamId,
            'member_id' => $this->member->id,
            'member_name' => $this->member->name,
            'member_email' => $this->member->email,
            'role' => $role->value,
        ]);
    }
}
