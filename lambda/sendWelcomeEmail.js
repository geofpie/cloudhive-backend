import { SNSClient, SubscribeCommand } from "@aws-sdk/client-sns";

const snsClient = new SNSClient({ region: 'us-east-1' }); // Replace with your region

export const handler = async (event) => {
    const { email, username } = JSON.parse(event.body);

    const topicArn = 'arn:aws:sns:us-east-1:576047115698:cloudhiveUserRegistration'; // Replace with your SNS topic ARN

    // Parameters to subscribe the email address to the SNS topic
    const subscribeParams = {
        Protocol: 'email',
        Endpoint: email,
        TopicArn: topicArn
    };

    try {
        // Subscribe the email address to the SNS topic
        await snsClient.send(new SubscribeCommand(subscribeParams));
        console.log(`Subscription request sent to ${email}`);
        
        // Publish a welcome message
        const publishParams = {
            Message: `Welcome ${username}! Thank you for registering at CloudHive.`,
            Subject: 'Welcome to CloudHive!',
            TopicArn: topicArn,
        };
        
        // Publish message to SNS topic
        await snsClient.send(new PublishCommand(publishParams));
        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Email sent and subscription request sent successfully' }),
        };
    } catch (error) {
        console.error('Error:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Error processing request' }),
        };
    }
};
