### Before submitting your new feature request:

< TODO: Drop this section >

- Check if your feature request has already been reported.
- Keep in mind that if there's a new feature that you want to see added to
amdgpu, this will be handled as a best effort. If this new feature is super
important to you, you'll need to write the code yourself - or convince someone
else to partner with you to write the code.
- Make sure that you are using the correct template.

Otherwise, fill the requested information below.
And please remove anything that doesn't apply to keep things readable :)

## Describe the problem

What is the problem that you want to solve?

## Describe the new feature behavior

Make sure that you explain how do you expect that the feature should work. Add
details on how this new feature will address the problem that you highlighted
in the previous section.

## Describe the target user/application

Keep in mind that the primary client for a driver feature is the userspace; for
this reason, start by describing the problem that the userspace has.
Additionally, try to highlight how the new feature will impact other apps or
users. Remember, we don't want to break userspace applications by adding a new
feature.

## How do you plan to validate this feature

Explain how the userspace will benefit from this new feature. Are you going to
implement something in an app to demonstrate the utilization? Are you going to
add IGT or kunit tests for that?

## Business case

Do you see a business case for this feature? For example, this feature will
improve the battery life in Z% or reduce the latency in case X.

## Draft of the userspace API

Make a draft that shows how the userspace will interact with this new feature.
Don't be afraid to add details here.

/label ~feature-request
