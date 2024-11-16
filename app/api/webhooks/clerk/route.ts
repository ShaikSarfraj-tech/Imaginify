import { clerkClient } from '@clerk/nextjs/server';  // Import the Clerk client
import { WebhookEvent } from '@clerk/nextjs/server';  // Import WebhookEvent type from Clerk
import { Webhook } from 'svix';  // Import the Svix Webhook class
import { headers } from 'next/headers';  // Import headers from Next.js

export async function POST(req: Request) {
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

  if (!WEBHOOK_SECRET) {
    throw new Error('Please add WEBHOOK_SECRET from Clerk Dashboard to .env or .env.local');
  }

  // Create new Svix instance with the Webhook Secret
  const wh = new Webhook(WEBHOOK_SECRET);

  // Get headers (await to resolve the promise)
  const headerPayload = await headers();
  const svix_id = headerPayload.get('svix-id');
  const svix_timestamp = headerPayload.get('svix-timestamp');
  const svix_signature = headerPayload.get('svix-signature');

  // If there are no headers, error out
  if (!svix_id || !svix_timestamp || !svix_signature) {
    return new Response('Error: Missing Svix headers', { status: 400 });
  }

  // Get body
  const payload = await req.json();
  const body = JSON.stringify(payload);

  let evt: WebhookEvent;

  // Verify payload with headers
  try {
    evt = wh.verify(body, {
      'svix-id': svix_id,
      'svix-timestamp': svix_timestamp,
      'svix-signature': svix_signature,
    }) as WebhookEvent;
  } catch (err) {
    console.error('Error: Could not verify webhook:', err);
    return new Response('Error: Verification error', { status: 400 });
  }

  // Handle specific webhook events
  const { id } = evt.data;
  const eventType = evt.type;

  // CREATE
  if (eventType === 'user.created') {
    const { email_addresses, image_url, first_name, last_name, username } = evt.data;

    const user = {
      clerkId: id,
      email: email_addresses[0].email_address,
      username: username!,
      firstName: first_name,
      lastName: last_name,
      photo: image_url,
    };

    try {
      const client = await clerkClient();  // Await the client first
      const newUser = await client.users.createUser({  // Correct method name: `createUser`
        emailAddress: [user.email],  // Pass emailAddress as an array
        firstName: user.firstName?.toString(),
        lastName: user.lastName?.toString(),
        username: user.username,
        // profile_image_url: user.photo,  // Correct property name here
      });

      // Optionally set public metadata
      if (newUser) {
        await client.users.updateUserMetadata(newUser.id, {
          publicMetadata: { userId: newUser.id },
        });
      }

      return new Response(JSON.stringify({ message: 'OK', user: newUser }), { status: 200 });
    } catch (error) {
      console.error('Error creating user:', error);
      return new Response('Error creating user', { status: 500 });
    }
  }

  // UPDATE
  if (eventType === 'user.updated') {
    if (!id) {
      return new Response('Error: Missing user ID', { status: 400 });
    }
    const { image_url, first_name, last_name, username } = evt.data;

    const user = {
      firstName: first_name,
      lastName: last_name,
      username: username!,
      photo: image_url,
    };

    try {
      const client = await clerkClient();  // Await the client first
      const updatedUser = await client.users.updateUser(id, {  // Use `updateUser`
        firstName: user.firstName?.toString(),
        lastName: user.lastName?.toString(),
        username: user.username,
        // profile_image_url: user.photo,  // Correct property name here
      });

      return new Response(JSON.stringify({ message: 'OK', user: updatedUser }), { status: 200 });
    } catch (error) {
      console.error('Error updating user:', error);
      return new Response('Error updating user', { status: 500 });
    }
  }

  // DELETE
  if (eventType === 'user.deleted') {
    if (!id) {
      return new Response('Error: Missing user ID', { status: 400 });
    }

    try {
      const client = await clerkClient();  // Await the client first
      await client.users.deleteUser(id);  // Use `deleteUser`

      return new Response(JSON.stringify({ message: 'OK', userId: id }), { status: 200 });
    } catch (error) {
      console.error('Error deleting user:', error);
      return new Response('Error deleting user', { status: 500 });
    }
  }

  // Log the event
  console.log(`Received webhook with ID ${id} and event type of ${eventType}`);
  console.log('Webhook payload:', body);

  return new Response('Webhook received', { status: 200 });
}
